#include "global.h"
#include <windows.h>
#include <ws2tcpip.h>
#include <shellapi.h>
#include <stdio.h>
#include <array>
#include <string>
#include <format>
#include "SftpClient.h"
#include "PluginEntryPoints.h"
#include "fsplugin.h"
#include "ServerRegistry.h"
#include "res/resource.h"
#include "CoreUtils.h"
#include "UtfConversion.h"
#include "SftpInternal.h"
#include "LngLoader.h"
#include "PpkConverter.h"

#define AUTH_LOG(fmt, ...) SFTP_LOG("AUTH", fmt, ##__VA_ARGS__)

static bool PromptLooksLikePasswordRequest(const char* promptTextLower) noexcept
{
    if (!promptTextLower || !promptTextLower[0])
        return false;
    if (!strstr(promptTextLower, "password"))
        return false;
    // Exclude common OTP / MFA prompts.
    if (strstr(promptTextLower, "oath") || strstr(promptTextLower, "otp") ||
        strstr(promptTextLower, "one time") || strstr(promptTextLower, "one-time") ||
        strstr(promptTextLower, "verification") || strstr(promptTextLower, "passcode") ||
        strstr(promptTextLower, "token"))
        return false;
    return true;
}

struct StoredSecretParts {
    bool labelled = false;
    std::string loginPassword;
    std::string keyPassphrase;
    ~StoredSecretParts()
    {
        if (!loginPassword.empty()) {
            loginPassword.resize(loginPassword.capacity());
            SecureZeroMemory(loginPassword.data(), loginPassword.size());
        }
        if (!keyPassphrase.empty()) {
            keyPassphrase.resize(keyPassphrase.capacity());
            SecureZeroMemory(keyPassphrase.data(), keyPassphrase.size());
        }
    }
};

static StoredSecretParts SplitStoredSecretLocal(const std::string& stored)
{
    StoredSecretParts out;
    // Dual-password format: "key_passphrase","login_password"
    if (stored.size() >= 5 && stored.front() == '"' && stored.back() == '"') {
        const size_t sep = stored.find("\",\"");
        if (sep != std::string::npos) {
            out.labelled      = true;
            out.keyPassphrase = stored.substr(1, sep - 1);
            out.loginPassword = stored.substr(sep + 3, stored.size() - sep - 4);
            return out;
        }
    }
    out.loginPassword = stored;
    out.keyPassphrase = stored;
    return out;
}

extern "C"
void kbd_callback(LPCSTR name, int name_len,
                  LPCSTR instruction, int instruction_len, int num_prompts,
                  const LIBSSH2_USERAUTH_KBDINT_PROMPT * prompts,
                  LIBSSH2_USERAUTH_KBDINT_RESPONSE * responses,
                  LPVOID * abstract)
{
    std::array<char, 256> retbuf{};
    struct WipeRet {
        char* ptr;
        size_t len;
        ~WipeRet() { SecureZeroMemory(ptr, len); }
    } wipeRet{retbuf.data(), retbuf.size()};
    pConnectSettings ConnectSettings = static_cast<pConnectSettings>(*abstract);

    StoredSecretParts secret;
    if (ConnectSettings && !ConnectSettings->password.empty())
        secret = SplitStoredSecretLocal(ConnectSettings->password);

    const bool storedUsableForLogin =
        ConnectSettings &&
        !secret.loginPassword.empty() &&
        (!ConnectSettings->key_passphrase_used || secret.labelled);

    for (int i = 0; i < num_prompts; i++) {
        // Pass the stored password as the first response for password-like prompts.
        // Multiple callback invocations are tracked via InteractivePasswordSent.
        const size_t copyLen = min(static_cast<size_t>(prompts[i].length), retbuf.size() - 1);
        memcpy(retbuf.data(), prompts[i].text, copyLen);
        retbuf[copyLen] = '\0';
        ShowStatus(retbuf.data());
        _strlwr_s(retbuf.data(), retbuf.size());
        const bool passwordPrompt = PromptLooksLikePasswordRequest(retbuf.data());
        // Never auto-send the stored password to "New password" / "Retype new password" prompts.
        const bool newPasswordPrompt = passwordPrompt && strstr(retbuf.data(), "new") != nullptr;
        bool autoSendPassword = passwordPrompt && !newPasswordPrompt && storedUsableForLogin &&
            !ConnectSettings->InteractivePasswordSent;
        if (autoSendPassword) {
            ConnectSettings->InteractivePasswordSent = true;
            responses[i].text = _strdup(secret.loginPassword.c_str());
            if (responses[i].text) {
                responses[i].length = (unsigned int)strlen(responses[i].text);
                ShowStatusId(IDS_LOG_SEND_STORED_PASS, nullptr, true);
            } else {
                autoSendPassword = false;
            }
        }
        if (!autoSendPassword) {
            std::string promptMsg;
            if (instruction && instruction_len)
                promptMsg = std::string(instruction, instruction_len) + "\n";
            if (prompts[i].length && prompts[i].text)
                promptMsg += std::string(reinterpret_cast<LPCSTR>(prompts[i].text), prompts[i].length);
            if (promptMsg.empty())
                promptMsg = "Password:";

            std::string title;
            if (name && name_len)
                title.assign(name, static_cast<size_t>(name_len));
            else
                title = "SFTP password for";
            if (ConnectSettings)
                title = std::format("{} {}@{}", title, ConnectSettings->user, ConnectSettings->server);
            SecureZeroMemory(retbuf.data(), retbuf.size());

            ShowStatusId(IDS_LOG_REQUEST_PASS, nullptr, true);
            bool answered = false;
            if (ConnectSettings && ConnectSettings->feedback) {
                std::string entered;
                answered = ConnectSettings->feedback->RequestText(title, promptMsg, entered, true);
                if (answered)
                    strlcpy(retbuf.data(), entered.c_str(), retbuf.size() - 1);
                if (!entered.empty()) {
                    entered.resize(entered.capacity());
                    SecureZeroMemory(entered.data(), entered.size());
                }
            } else if (RequestProc) {
                answered = RequestProc(PluginNumber, RT_Password, title.c_str(), promptMsg.c_str(), retbuf.data(), retbuf.size()-1) != 0;
            }
            if (ConnectSettings)
                ConnectSettings->authPromptDone = get_sys_ticks();
            if (answered) {
                responses[i].text = _strdup(retbuf.data());
                responses[i].length = (unsigned int)strlen(retbuf.data());
                // Hold typed password separately until login succeeds so a mistyped
                // password is not immediately replayed on the next method/prompt.
                if (ConnectSettings) {
                    if (newPasswordPrompt)
                        ConnectSettings->changed_password = retbuf.data();
                    else if (passwordPrompt)
                        ConnectSettings->typed_password = retbuf.data();
                }
                ShowStatusId(IDS_LOG_SEND_USER_PASS, nullptr, true);
            } else {
                responses[i].text = nullptr;
                responses[i].length = 0;
            }
            SecureZeroMemory(retbuf.data(), retbuf.size());
        }
    }
} /* kbd_callback */

static bool ismimechar(const char ch)
{
    return ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
             ch == '/' || ch == '+' || ch == '=' || ch == '\r' || ch == '\n');
}

static bool EndsWithNoCase(LPCSTR text, LPCSTR suffix) noexcept
{
    if (!text || !suffix)
        return false;
    size_t tlen = strlen(text);
    size_t slen = strlen(suffix);
    if (tlen < slen)
        return false;
    return _stricmp(text + tlen - slen, suffix) == 0;
}

static void ShowPpkConversionFailure(PpkConvertError convErr)
{
    switch (convErr) {
    case PpkConvertError::unsupported_version:
        ShowStatusId(IDS_LOG_PPK_ERR_VERSION, nullptr, true);
        break;
    case PpkConvertError::unsupported_algorithm:
        ShowStatusId(IDS_LOG_PPK_ERR_ALGO, nullptr, true);
        break;
    case PpkConvertError::unsupported_encryption:
    case PpkConvertError::unsupported_kdf:
        ShowStatusId(IDS_LOG_PPK_ERR_ENC, nullptr, true);
        break;
    case PpkConvertError::kdf_unavailable:
        ShowStatusId(IDS_LOG_PPK_ERR_ARGON2, nullptr, true);
        break;
    case PpkConvertError::passphrase_required:
    case PpkConvertError::bad_passphrase_or_mac:
        ShowStatusId(IDS_LOG_PPK_ERR_PASSPHRASE, nullptr, true);
        break;
    default:
        ShowStatusId(IDS_LOG_PPK_ERR_GENERIC, nullptr, true);
        break;
    }
}

static void ExpandAuthPath(char* path, size_t pathLen, LPCSTR user)
{
    if (!path || pathLen == 0)
        return;
    ReplaceSubString(path, "%USER%", user ? user : "", pathLen - 1);
    ReplaceEnvVars(path, pathLen - 1);
}

static bool DetectPrivateKeyEncrypted(LPCSTR privkeyfile, bool* outEncrypted)
{
    if (!privkeyfile || !outEncrypted)
        return false;

    DWORD dwShareMode = FILE_SHARE_READ | FILE_SHARE_WRITE;
    DWORD dwFlags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN;
    handle_util::FileHandle hf(CreateFileA(privkeyfile, GENERIC_READ, dwShareMode, nullptr, OPEN_EXISTING, dwFlags, nullptr));
    if (!hf)
        return false;

    std::array<char, 1024> filebuf{};
    DWORD dataread = 0;
    bool isencrypted = true;
    if (ReadFile(hf.get(), filebuf.data(), static_cast<DWORD>(filebuf.size() - 32), &dataread, nullptr)) {
        filebuf[dataread] = 0;
        LPSTR p = strchr(filebuf.data(), '\n');
        if (!p)
            p = strchr(filebuf.data(), '\r');
        if (p) {
            p++;
            while (p[0] == '\r' || p[0] == '\n')
                p++;
            isencrypted = false;
            for (int i = 0; i < 32; i++)
                if (!ismimechar(p[i]))
                    isencrypted = true;
            if (!isencrypted) {
                char* p2 = filebuf.data();
                while (p2[0] == '\r' || p2[0] == '\n')
                    p2++;
                if (strncmp(p2, "-----BEGIN OPENSSH PRIVATE KEY-----", 35) == 0) {
                    std::array<char, 64> outbuf{};
                    int len = MimeDecode(p, min(64, strlen(p)), outbuf.data(), outbuf.size());
                    for (int i = 0; i < len - 6; i++) {
                        if (outbuf[i] == 'b' && strncmp(outbuf.data() + i, "bcrypt", 6) == 0) {
                            isencrypted = true;
                            break;
                        }
                    }
                }
            }
        }
    }
    *outEncrypted = isencrypted;
    return true;
}

static void BuildUserAtServerTitle(char* out, size_t outLen, int prefixResId, pConnectSettings cs)
{
    if (!out || outLen == 0)
        return;
    out[0] = 0;
    LoadStr(out, outLen, prefixResId);
    if (!cs)
        return;
    strlcat(out, cs->user.c_str(), outLen - 1);
    strlcat(out, "@", outLen - 1);
    strlcat(out, cs->server.c_str(), outLen - 1);
}

static bool PreparePrivateKeyForAuth(
    pConnectSettings cs,
    char* ioPrivKeyFile,
    size_t privKeyLen,
    char** ioPubKeyPtr,
    bool* outRemoveConvertedPrivateKey,
    char* outConvertedPrivateKey,
    size_t convertedLen,
    char* ioPromptBuf,
    size_t ioPromptBufLen)
{
    if (!cs || !ioPrivKeyFile || !ioPubKeyPtr || !outRemoveConvertedPrivateKey || !outConvertedPrivateKey || !ioPromptBuf)
        return false;
    if (!EndsWithNoCase(ioPrivKeyFile, ".ppk"))
        return true;

    const StoredSecretParts secret = SplitStoredSecretLocal(cs->password);
    const char* ppkPass = secret.keyPassphrase.empty() ? "" : secret.keyPassphrase.c_str();
    PpkConvertError convErr = PpkConvertError::internal_error;
    ShowStatusId(IDS_LOG_PPK_CONVERTING, nullptr, true);
    bool converted = ConvertPpkToOpenSsh(ioPrivKeyFile, ppkPass, outConvertedPrivateKey, convertedLen - 1, &convErr);
    if (converted && !secret.keyPassphrase.empty())
        cs->key_passphrase_used = true;
    const std::string convStatus = std::format("PPK conv: {}, err={}", converted, static_cast<int>(convErr));
    AUTH_LOG("PPK conversion: converted=%d, convErr=%d, pemPath=%s", converted, convErr, outConvertedPrivateKey);
    ShowStatus(convStatus.c_str());

    bool userCancelled = false;
    for (int tries = 0; !converted && tries < 3 &&
         (convErr == PpkConvertError::passphrase_required ||
          convErr == PpkConvertError::bad_passphrase_or_mac); ++tries) {
        std::array<char, 250> title{};
        std::array<char, 256> ppkPassBuf{};
        LoadStr(ioPromptBuf, ioPromptBufLen, IDS_KEYPASSPHRASE);
        BuildUserAtServerTitle(title.data(), title.size(), IDS_PASSPHRASE, cs);
        bool answered = false;
        if (cs->feedback) {
            std::string entered;
            answered = cs->feedback->RequestText(title.data(), ioPromptBuf, entered, true);
            if (answered)
                strlcpy(ppkPassBuf.data(), entered.c_str(), ppkPassBuf.size() - 1);
            if (!entered.empty()) {
                entered.resize(entered.capacity());
                SecureZeroMemory(entered.data(), entered.size());
            }
        } else if (RequestProc) {
            answered = RequestProc(PluginNumber, RT_Password, title.data(), ioPromptBuf, ppkPassBuf.data(), ppkPassBuf.size() - 1) != 0;
        }
        cs->authPromptDone = get_sys_ticks();
        if (!answered) {
            userCancelled = true;
            SecureZeroMemory(ppkPassBuf.data(), ppkPassBuf.size());
            break;
        }
        converted = ConvertPpkToOpenSsh(ioPrivKeyFile, ppkPassBuf.data(), outConvertedPrivateKey, convertedLen - 1, &convErr);
        if (converted)
            cs->key_passphrase_used = true;
        SecureZeroMemory(ppkPassBuf.data(), ppkPassBuf.size());
    }

    if (!converted) {
        ShowPpkConversionFailure(convErr);
        if (!userCancelled && convErr == PpkConvertError::bad_passphrase_or_mac && cs->feedback)
            cs->feedback->ShowError(LngStrU8(IDS_LOG_PPK_ERR_PASSPHRASE, "Incorrect PPK passphrase or key MAC check failed.").c_str());
        return false;
    }

    strlcpy(ioPrivKeyFile, outConvertedPrivateKey, privKeyLen - 1);
    *ioPubKeyPtr = nullptr;
    *outRemoveConvertedPrivateKey = true;
    return true;
}

static bool ValidatePublicKeyFileIfPresent(
    char* pubkeyfileptr,
    LPCSTR convertedPrivateKey,
    bool removeConvertedPrivateKey,
    LPCSTR pubkeyfile,
    DWORD dwShareMode,
    DWORD dwFlags)
{
    if (!pubkeyfileptr || !pubkeyfile[0])
        return true;

    DWORD dataread = 0;
    std::array<char, 1024> filebuf{};
    handle_util::FileHandle hf(CreateFileA(pubkeyfile, GENERIC_READ, dwShareMode, nullptr, OPEN_EXISTING, dwFlags, nullptr));
    if (!hf) {
        if (removeConvertedPrivateKey)
            DeleteFileA(convertedPrivateKey);
        ShowStatusId(IDS_ERR_LOAD_PUBKEY, pubkeyfile, true);
        return false;
    }

    if (ReadFile(hf.get(), filebuf.data(), 35, &dataread, nullptr)) {
        if (_strnicmp(filebuf.data(), "ssh-", 4) != 0 &&
            _strnicmp(filebuf.data(), "ecdsa-", 6) != 0 &&
            _strnicmp(filebuf.data(), "-----BEGIN OPENSSH PRIVATE KEY-----", 35) != 0 &&
            _strnicmp(filebuf.data(), "-----BEGIN RSA PRIVATE KEY-----", 31) != 0 &&
            _strnicmp(filebuf.data(), "-----BEGIN EC PRIVATE KEY-----", 30) != 0)
        {
            if (removeConvertedPrivateKey)
                DeleteFileA(convertedPrivateKey);
            ShowStatusId(IDS_ERR_PUBKEY_WRONG_FORMAT, nullptr, true);
            return false;
        }
    }
    return true;
}


int SftpAuthPageant(pConnectSettings ConnectSettings, LPCSTR progressbuf, int progress, int * ploop, SYSTICKS * plasttime, int * auth_pw)
{
    std::array<char, 1024> buf{};
    struct libssh2_agent_publickey * identity = nullptr;
    struct libssh2_agent_publickey * prev_identity = nullptr;

    std::unique_ptr<ISshAgent> agent = ConnectSettings->session->agentInit();
    auto finish = [&](int code) -> int {
        if (code < 0) {
            ShowStatusId(-code, nullptr, true);
        } else if (code == 0) {
            ShowStatusId(IDS_AGENT_AUTHSUCCEEDED, nullptr, true);
        }
        if (agent) {
            agent->disconnect();
        }
        return code;
    };

    if (!agent || agent->connect() != 0) {
        if (agent) {
            agent->disconnect();
            // agent->free() removed: ~Libssh2Agent() calls libssh2_agent_free()
            agent.reset();
        }
        // Attempt to launch Pageant.
        std::array<char, MAX_PATH> dirname{};
        dirname[0] = 0;
        GetModuleFileName(hinst, dirname.data(), dirname.size()-10);
        char* p = strrchr(dirname.data(), '\\');
        p = p ? p + 1 : dirname.data();
        p[0] = 0;
        const std::string linkname = std::string(dirname.data()) + "pageant.lnk";
        if (GetFileAttributesA(linkname.c_str()) == INVALID_FILE_ATTRIBUTES)
            return finish(-IDS_AGENT_CONNECTERROR);

        HWND active = GetForegroundWindow();
        ShellExecute(active, nullptr, linkname.c_str(), nullptr, dirname.data(), SW_SHOW);
        Sleep(PAGEANT_WAIT_MS);
        SYSTICKS starttime = get_sys_ticks();
        while (active != GetForegroundWindow() && get_ticks_between(starttime) < PAGEANT_TIMEOUT_MS) {
            Sleep(200);
            if (ProgressLoop(progressbuf, progress, progress + 5, ploop, plasttime))
                break;
        }
        agent = ConnectSettings->session->agentInit();
        if (!agent)
            return finish(-IDS_AGENT_CONNECTERROR);
        int rc = agent->connect();
        if (rc)
            return finish(-IDS_AGENT_CONNECTERROR);
    }

    int rc = agent->listIdentities();
    if (rc)
        return finish(-IDS_AGENT_REQUESTIDENTITIES);
    while (1) {
        int auth = agent->getIdentity(&identity, prev_identity);
        if (auth == 1)
            return finish(-IDS_AGENT_AUTHFAILED);  /* pub key */
        if (auth < 0)
            return finish(-IDS_AGENT_NOIDENTITY);
        std::array<char, 128> str1{}, str2{}, str3{};
        LoadStr(str1, IDS_AGENT_TRYING1);
        LoadStr(str2, IDS_AGENT_TRYING2);
        LoadStr(str3, IDS_AGENT_TRYING3);
        ShowStatus((std::string(str1.data()) + ConnectSettings->user + str2.data() + identity->comment + str3.data()).c_str());
        const SYSTICKS authStart = get_sys_ticks();
        while ((auth = agent->userauth(ConnectSettings->user.c_str(), identity)) == LIBSSH2_ERROR_EAGAIN) {
            if (ProgressLoop(progressbuf, progress, progress + 5, ploop, plasttime))
                return finish(-IDS_AGENT_AUTHFAILED);
            if (get_ticks_between(authStart) > SSH_AUTH_STAGE_TIMEOUT_MS) {
                ShowStatusId(IDS_LOG_PAGEANT_TIMEOUT, nullptr, true);
                return finish(-IDS_AGENT_AUTHFAILED);
            }
            WaitForSshIo(ConnectSettings);
        }
#ifndef SFTP_ALLINONE
        // NOTE: LIBSSH2_ERROR_REQUIRE_KEYBOARD / REQUIRE_PASSWORD are non-standard error codes
        // provided by the local libssh2 fork to signal mid-auth method switching.
        if (auth == LIBSSH2_ERROR_REQUIRE_KEYBOARD) {
            *auth_pw = SSH_AUTH_KEYBOARD;
            return finish(SSH_AUTH_KEYBOARD);
        }
        if (auth == LIBSSH2_ERROR_REQUIRE_PASSWORD) {
            *auth_pw = SSH_AUTH_PASSWORD;
            return finish(SSH_AUTH_PASSWORD);
        }
#endif
        if (auth == 0)
            return finish(0);   /* OK */
        prev_identity = identity;
    }
}

int SftpAuthPubKey(pConnectSettings ConnectSettings, LPCSTR progressbuf, int progress, int * ploop, SYSTICKS * plasttime, int * auth_pw)
{
    std::array<char, 1024> buf{};
    std::array<char, 256> passphrase{};
    std::array<char, wdirtypemax> pubkeyfile{};
    std::array<char, wdirtypemax> privkeyfile{};
    std::array<char, wdirtypemax> convertedPrivateKey{};
    bool removeConvertedPrivateKey = false;
    char* pubkeyfileptr = pubkeyfile.data();
    auto cleanupConvertedIfNeeded = [&]() {
        if (removeConvertedPrivateKey)
            DeleteFileA(convertedPrivateKey.data());
    };
    auto clearPassphrase = [&]() {
        SecureZeroMemory(passphrase.data(), passphrase.size());
    };

    AUTH_LOG("=== SftpAuthPubKey START ===");
    // Check if LogProc is available
    extern tLogProc LogProc;
    if (LogProc) LogProc(PluginNumber, MSGTYPE_DETAILS, "=== SftpAuthPubKey called from SftpConnection ===");
    AUTH_LOG("privkeyfile=%s", ConnectSettings->privkeyfile.c_str());
    AUTH_LOG("pubkeyfile=%s", ConnectSettings->pubkeyfile.c_str());
    AUTH_LOG("password_empty=%d", ConnectSettings->password.empty() ? 1 : 0);
    AUTH_LOG("server=%s", ConnectSettings->server.c_str());
    AUTH_LOG("user=%s", ConnectSettings->user.c_str());

    strlcpy(pubkeyfile.data(), ConnectSettings->pubkeyfile.c_str(), pubkeyfile.size()-1);
    ExpandAuthPath(pubkeyfile.data(), pubkeyfile.size(), ConnectSettings->user.c_str());
    strlcpy(privkeyfile.data(), ConnectSettings->privkeyfile.c_str(), privkeyfile.size()-1);
    ExpandAuthPath(privkeyfile.data(), privkeyfile.size(), ConnectSettings->user.c_str());
    convertedPrivateKey[0] = 0;

    AUTH_LOG("After expand: privkeyfile=%s", privkeyfile.data());
    AUTH_LOG("After expand: pubkeyfile=%s", pubkeyfile.data());
    AUTH_LOG("privkeyfile exists=%d", GetFileAttributesA(privkeyfile.data()) != INVALID_FILE_ATTRIBUTES);

    // Fail-fast on explicit key paths that do not exist.
    if (privkeyfile.data()[0] && GetFileAttributesA(privkeyfile.data()) == INVALID_FILE_ATTRIBUTES) {
        ShowStatusId(IDS_ERR_LOAD_PRIVKEY, privkeyfile.data(), true);
        clearPassphrase();
        return -LIBSSH2_ERROR_FILE;
    }
    if (pubkeyfileptr && pubkeyfile.data()[0] && GetFileAttributesA(pubkeyfile.data()) == INVALID_FILE_ATTRIBUTES) {
        ShowStatusId(IDS_ERR_LOAD_PUBKEY, pubkeyfile.data(), true);
        clearPassphrase();
        return -LIBSSH2_ERROR_FILE;
    }

    if (!PreparePrivateKeyForAuth(ConnectSettings, privkeyfile.data(), privkeyfile.size(), &pubkeyfileptr,
                                  &removeConvertedPrivateKey, convertedPrivateKey.data(), convertedPrivateKey.size(),
                                  buf.data(), buf.size())) {
        clearPassphrase();
        return -LIBSSH2_ERROR_FILE;
    }

    passphrase[0] = 0;
    // verify that we have a valid public key file (optional when private key is enough)
    DWORD dwShareMode = FILE_SHARE_READ | FILE_SHARE_WRITE;
    DWORD dwFlags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN;
    if (!ValidatePublicKeyFileIfPresent(pubkeyfileptr, convertedPrivateKey.data(), removeConvertedPrivateKey, pubkeyfile.data(), dwShareMode, dwFlags))
    {
        clearPassphrase();
        return -LIBSSH2_ERROR_FILE;
    }

    // Skip passphrase prompt for unencrypted keys.
    // Converted PPK output PEM is unencrypted.
    bool isencrypted = true;  // Assume encrypted by default
    bool skipEncryptionCheck = removeConvertedPrivateKey;  // Converted PPK -> skip check, we know it's unencrypted
    
    if (!skipEncryptionCheck) {
        if (!DetectPrivateKeyEncrypted(privkeyfile.data(), &isencrypted)) {
            cleanupConvertedIfNeeded();
            ShowStatusId(IDS_ERR_LOAD_PRIVKEY, privkeyfile.data(), true);
            clearPassphrase();
            return -LIBSSH2_ERROR_FILE;
        }
    } else {
        // Converted from PPK; encryption is already known.
        isencrypted = false;
    }
    
    const std::string encStatus = std::format("Key: {}", isencrypted ? "encrypted" : "unencrypted");
    AUTH_LOG("Encryption check result: %s", encStatus.c_str());
    ShowStatus(encStatus.c_str());

    // Pass nullptr (not an empty buffer) when no public key file is set, so libssh2's
    // mbedTLS backend derives the public key from the private one instead of
    // calling fopen("") and failing with LIBSSH2_ERROR_FILE.
    if (pubkeyfileptr && (pubkeyfile.data()[0] == 0 ||
                          _stricmp(pubkeyfile.data(), privkeyfile.data()) == 0))
        pubkeyfileptr = nullptr;

    pConnectSettings cs = ConnectSettings;
    const StoredSecretParts storedSecret = SplitStoredSecretLocal(ConnectSettings->password);
    bool triedStoredPassphrase = false;
    bool cancelledPassphrase = false;
    int typedPassphraseTries = 0;
    int auth = LIBSSH2_ERROR_FILE;

    for (;;) {
        if (isencrypted) {
            if (!triedStoredPassphrase && !storedSecret.keyPassphrase.empty()) {
                triedStoredPassphrase = true;
                strlcpy(passphrase.data(), storedSecret.keyPassphrase.c_str(), passphrase.size() - 1);
            } else {
                if (typedPassphraseTries >= 3)
                    break;
                ++typedPassphraseTries;
                SecureZeroMemory(passphrase.data(), passphrase.size());
                std::array<char, 250> title{};
                BuildUserAtServerTitle(title.data(), title.size(), IDS_PASSPHRASE, ConnectSettings);
                LoadStr(buf, IDS_KEYPASSPHRASE);
                bool answered = false;
                if (ConnectSettings->feedback) {
                    std::string entered;
                    answered = ConnectSettings->feedback->RequestText(title.data(), buf.data(), entered, true);
                    if (answered)
                        strlcpy(passphrase.data(), entered.c_str(), passphrase.size() - 1);
                    if (!entered.empty()) {
                        entered.resize(entered.capacity());
                        SecureZeroMemory(entered.data(), entered.size());
                    }
                } else if (RequestProc) {
                    answered = RequestProc(PluginNumber, RT_Password, title.data(), buf.data(), passphrase.data(), passphrase.size() - 1) != 0;
                }
                ConnectSettings->authPromptDone = get_sys_ticks();
                if (!answered) {
                    cancelledPassphrase = true;
                    break;
                }
            }
        }

        ShowStatusId(IDS_AUTH_PUBKEY_FOR, ConnectSettings->user.c_str(), true);
        LoadStr(buf, IDS_AUTH_PUBKEY);
        const char* passphrasePtr = isencrypted ? passphrase.data() : nullptr;
        AUTH_LOG("Calling userauthPubkeyFromFile: priv=%s pub=%s passphrase=%s",
                 privkeyfile.data(),
                 pubkeyfileptr ? pubkeyfileptr : "(null)",
                 passphrasePtr ? "(set)" : "(null)");
        const SYSTICKS authStart = get_sys_ticks();
        while ((auth = cs->session->userauthPubkeyFromFile(cs->user.c_str(), (unsigned)cs->user.size(), pubkeyfileptr, privkeyfile.data(), passphrasePtr)) == LIBSSH2_ERROR_EAGAIN) {
            if (ProgressLoop(buf.data(), progress, progress + 10, ploop, plasttime)) {
                cancelledPassphrase = true;
                break;
            }
            if (get_ticks_between(authStart) > SSH_AUTH_STAGE_TIMEOUT_MS) {
                ShowStatusId(IDS_LOG_PUBKEY_TIMEOUT, nullptr, true);
                auth = LIBSSH2_ERROR_TIMEOUT;
                break;
            }
            WaitForSshIo(ConnectSettings);
        }
        AUTH_LOG("userauthPubkeyFromFile result=%d", auth);
        if (auth == 0 || !isencrypted || cancelledPassphrase)
            break;

        char* errMsg = nullptr;
        int errLen = 0;
        ConnectSettings->session->lastError(&errMsg, &errLen, false);
        const bool likelyBadPassphrase =
            (auth == LIBSSH2_ERROR_FILE) ||
            (auth == LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED && errMsg &&
             (strstr(errMsg, "passphrase") || strstr(errMsg, "decrypt") ||
              strstr(errMsg, "Unable to extract public key") || strstr(errMsg, "private key")));
        if (!likelyBadPassphrase) {
            // Key itself decrypted fine — server rejected the key.
            // Mark key_passphrase_used so we do not send this passphrase as login password.
            if (isencrypted && triedStoredPassphrase && typedPassphraseTries == 0)
                ConnectSettings->key_passphrase_used = true;
            break;
        }
    }

    if (auth == 0 && isencrypted && triedStoredPassphrase && typedPassphraseTries == 0)
        ConnectSettings->key_passphrase_used = true;

    if (auth) {
        cleanupConvertedIfNeeded();
        char* errMsg = nullptr;
        int errLen = 0;
        ConnectSettings->session->lastError(&errMsg, &errLen, false);
        SftpLogLastError("libssh2_userauth_publickey_fromfile: ", auth);
        if (!cancelledPassphrase) {
            std::array<char, 1024> loadedMsg{};
            LoadStr(loadedMsg, IDS_ERR_AUTH_PUBKEY);
            std::string uiMsg;
            if (loadedMsg[0] == 0 || _stricmp(loadedMsg.data(), "Error:") == 0 || strstr(loadedMsg.data(), "%s"))
                uiMsg = "Error: Authentication by client certificate failed!";
            else
                uiMsg = loadedMsg.data();
            if (errMsg && errMsg[0])
                uiMsg += "\n" + std::string(errMsg);
            const bool hasFallbackAuth =
                auth_pw && ((*auth_pw & SSH_AUTH_PASSWORD) != 0 || (*auth_pw & SSH_AUTH_KEYBOARD) != 0);
            if (hasFallbackAuth) {
                // Avoid modal noise when we can continue with password/keyboard.
                ShowStatus(uiMsg.c_str());
            } else {
                ShowError(uiMsg.c_str());
            }
        }
        AUTH_LOG("SftpAuthPubKey returning -IDS_ERR_AUTH_PUBKEY");
        clearPassphrase();
        return -IDS_ERR_AUTH_PUBKEY;
    }
    cleanupConvertedIfNeeded();

    clearPassphrase();
    AUTH_LOG("SftpAuthPubKey returning 0 (SUCCESS)");
    return 0;
}
