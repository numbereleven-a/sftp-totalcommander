#include "global.h"
#include <windows.h>
#include <algorithm>
#include <array>
#include <string>
#include <format>
#include "SftpClient.h"
#include "PluginEntryPoints.h"
#include "SftpInternal.h"
#include "ProxyNegotiator.h"
#include "IUserFeedback.h"
#include "AuthMethodParser.h"
#include "ConnectionAuth.h"
#include "res/resource.h"

namespace {

struct LoginSecretSplit {
    bool labelled = false;
    std::string loginPassword;
    std::string keyPassphrase;
    ~LoginSecretSplit()
    {
        for (std::string* s : { &loginPassword, &keyPassphrase }) {
            if (!s->empty()) {
                s->resize(s->capacity());
                SecureZeroMemory(s->data(), s->size());
            }
        }
    }
};

LoginSecretSplit SplitLoginSecret(const std::string& stored)
{
    LoginSecretSplit out;
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

void PersistChangedLoginPassword(pConnectSettings cs, const std::string& newLoginPass)
{
    if (!cs)
        return;
    const LoginSecretSplit old = SplitLoginSecret(cs->password);
    std::string stored = newLoginPass;
    if (old.labelled)
        stored = "\"" + old.keyPassphrase + "\",\"" + newLoginPass + "\"";
    cs->password = stored;

    if (!cs->DisplayName.empty() && !cs->IniFileName.empty()) {
        switch (cs->passSaveMode) {
        case sftp::PassSaveMode::crypt:
            if (CryptProc) {
                if (CryptProc(PluginNumber, CryptoNumber, FS_CRYPT_SAVE_PASSWORD,
                              cs->DisplayName.c_str(), const_cast<char*>(stored.c_str()), 0) != FS_FILE_OK) {
                    ShowStatus("Password manager refused to save the changed password.");
                }
            }
            break;
        case sftp::PassSaveMode::plain:
            if (stored.empty()) {
                WritePrivateProfileString(cs->DisplayName.c_str(), "password", nullptr, cs->IniFileName.c_str());
            } else {
                std::array<char, 8192> szEncryptedPassword{};
                EncryptString(stored.c_str(), szEncryptedPassword.data(), static_cast<UINT>(szEncryptedPassword.size()));
                if (szEncryptedPassword[0])
                    WritePrivateProfileString(cs->DisplayName.c_str(), "password", szEncryptedPassword.data(), cs->IniFileName.c_str());
                SecureZeroMemory(szEncryptedPassword.data(), szEncryptedPassword.size());
            }
            break;
        default:
            break;
        }
    }
    if (!stored.empty()) {
        stored.resize(stored.capacity());
        SecureZeroMemory(stored.data(), stored.size());
    }
}

void CommitAuthPasswords(pConnectSettings cs, bool loggedIn)
{
    if (!cs)
        return;
    if (loggedIn) {
        if (!cs->changed_password.empty()) {
            PersistChangedLoginPassword(cs, cs->changed_password);
        } else if (!cs->typed_password.empty() && cs->password.empty()) {
            cs->password = cs->typed_password;
        }
    }
    for (std::string* s : { &cs->typed_password, &cs->changed_password }) {
        if (!s->empty()) {
            s->resize(s->capacity());
            SecureZeroMemory(s->data(), s->size());
            s->clear();
        }
    }
}

} // namespace

extern "C"
void newpassfunc(LIBSSH2_SESSION* /*session*/, LPSTR* newpw, int* newpw_len, LPVOID* abstract)
{
    pConnectSettings PassConnectSettings = static_cast<pConnectSettings>(*abstract);
    std::array<char, 128> title{};
    std::array<char, 128> buf1{};
    std::array<char, 4096> newpass{};
    struct WipePassword { std::array<char, 4096>& value; ~WipePassword() { SecureZeroMemory(value.data(), value.size()); } } wipe{newpass};
    LoadStr(title, IDS_PASS_TITLE);
    LoadStr(buf1, IDS_PASS_CHANGE_REQUEST);
    newpass[0] = 0;
    if (newpw)
        *newpw = nullptr;
    if (newpw_len)
        *newpw_len = 0;
    const bool answered = RequestProc &&
        RequestProc(PluginNumber, RT_Password, title.data(), buf1.data(), newpass.data(), newpass.size()-1) != 0;
    if (PassConnectSettings)
        PassConnectSettings->authPromptDone = get_sys_ticks();
    if (answered) {
        size_t bufsize = strlen(newpass.data()) + 1;
        *newpw = static_cast<char*>(malloc(bufsize));
        if (!*newpw)
            return;
        strlcpy(*newpw, newpass.data(), bufsize);
        *newpw_len = (int)strlen(newpass.data());
        if (PassConnectSettings)
            PersistChangedLoginPassword(PassConnectSettings, newpass.data());
    }
}

int NegotiateProxy(
    pConnectSettings ConnectSettings,
    unsigned short connecttoport,
    int& progress,
    int& loop,
    SYSTICKS& lasttime)
{
    if (ConnectSettings->proxytype == sftp::Proxy::notused)
        return 0;

    progress = 20; // PROG_SOCKET_CONNECT
    std::array<char, 250> progressbuf{};
    LoadStr(progressbuf, IDS_PROXY_CONNECT);
    if (ProgressProc(PluginNumber, progressbuf.data(), "-", progress))
        return -40;

    int hr = 0;
    switch (ConnectSettings->proxytype) {
    case sftp::Proxy::http:
        hr = SftpConnectProxyHttp(ConnectSettings, progressbuf.data(), progress, &loop, &lasttime);
        if (hr) return -12040 - hr;
        break;
    case sftp::Proxy::socks4:
        hr = SftpConnectProxySocks4(ConnectSettings, progressbuf.data(), progress, &loop, &lasttime);
        if (hr) return -13040 - hr;
        break;
    case sftp::Proxy::socks5:
        hr = SftpConnectProxySocks5(ConnectSettings, connecttoport, progressbuf.data(), progress, &loop, &lasttime);
        if (hr) return -14040 - hr;
        break;
    default:
        break;
    }
    return 0;
}

int PerformAuthentication(
    pConnectSettings ConnectSettings,
    int& progress,
    int& loop,
    SYSTICKS& lasttime,
    char* progressbuf,
    bool agentAvailable)
{
    std::array<char, 1024> buf{};
    char* userauthlist = nullptr;
    int auth_pw = 0;
    const bool skipProbe = ConnectSettings->scponly
        || !ConnectSettings->password.empty()
        || !ConnectSettings->privkeyfile.empty();
    if (skipProbe) {
        ShowStatusId(IDS_LOG_SCP_SKIP_PROBE, nullptr, true);
        // Skip userauthList probe when credentials are known: avoids hanging on
        // servers (e.g. OVH) that respond slowly to the "none" auth request.
        auth_pw = SSH_AUTH_PASSWORD | SSH_AUTH_KEYBOARD | SSH_AUTH_PUBKEY;
    } else {
        SYSTICKS authListStart = get_sys_ticks();
        do {
            userauthlist = ConnectSettings->session->userauthList(ConnectSettings->user.c_str(), (UINT)ConnectSettings->user.size());
            LoadStr(buf, IDS_USER_AUTH_LIST);
            if (ProgressLoop(buf.data(), progress, progress + 10, &loop, &lasttime))
                break;
            if (get_ticks_between(authListStart) > SSH_PROBE_TIMEOUT_MS) {
                ShowStatusId(IDS_LOG_AUTH_METHODS_TIMEOUT, nullptr, true);
                break;
            }
            if (!userauthlist && ConnectSettings->session->lastErrno() == LIBSSH2_ERROR_EAGAIN)
                WaitForSshIo(ConnectSettings);
        } while (userauthlist == nullptr && ConnectSettings->session->lastErrno() == LIBSSH2_ERROR_EAGAIN);

        const std::string uaLog = std::format("userauthlist='{}' errno={}",
            userauthlist ? userauthlist : "(null)", ConnectSettings->session->lastErrno());
        ShowStatus(uaLog.c_str());

        if (userauthlist) {
            ShowStatusId(IDS_SUPPORTED_AUTH_METHODS, userauthlist, true);
            auth_pw = ParseAuthMethodsFromUserauthList(userauthlist);
            if (auth_pw == 0) {
                ShowStatusId(IDS_LOG_AUTH_METHODS_NONE, nullptr, true);
                // Some servers return malformed method lists; keep a compatibility path.
                auth_pw = SSH_AUTH_PASSWORD | SSH_AUTH_KEYBOARD | SSH_AUTH_PUBKEY;
            }
        } else {
            SftpLogLastError("libssh2_userauth_list: ", ConnectSettings->session->lastErrno());
            // NULL list after timeout/EAGAIN is treated as non-fatal for compatibility.
            auth_pw = SSH_AUTH_PASSWORD | SSH_AUTH_KEYBOARD | SSH_AUTH_PUBKEY;
        }
    }

    ConnectSettings->key_passphrase_used = false;
    ConnectSettings->authPromptDone = 0;

    int auth = 0;
    bool triedPubkey = false;
    if (ConnectSettings->session->userauthAuthenticated()) {
        ShowStatusId(IDS_LOG_AUTH_NO_PASSWORD, nullptr, true);
    } else {
        if ((auth_pw & SSH_AUTH_PUBKEY) && ConnectSettings->useagent && agentAvailable) {
            triedPubkey = true;
            progress = 65;
            int rc = SftpAuthPageant(ConnectSettings, progressbuf, progress, &loop, &lasttime, &auth_pw);
            auth = (rc < 0) ? LIBSSH2_ERROR_AGENT_PROTOCOL : 0;
            const std::string status = std::format("Pageant: rc={} auth={}", rc, auth);
            ShowStatus(status.c_str());
        }
        // Try configured key file even when useagent is enabled if Pageant did not authenticate.
        if ((!triedPubkey || auth != 0) && (auth_pw & SSH_AUTH_PUBKEY) && !ConnectSettings->privkeyfile.empty()) {
            triedPubkey = true;
            progress = 65;
            if (LogProc) LogProc(PluginNumber, MSGTYPE_DETAILS, "=== Calling SftpAuthPubKey ===");
            int rc = SftpAuthPubKey(ConnectSettings, progressbuf, progress, &loop, &lasttime, &auth_pw);
            auth = (rc < 0) ? LIBSSH2_ERROR_FILE : 0;
            if (rc == -LIBSSH2_ERROR_FILE) {
                SFTP_LOG("CONN", "Public-key auth aborted due to local key file error.");
                return SFTP_FAILED;
            }
            if (LogProc) LogProc(PluginNumber, MSGTYPE_DETAILS, "=== SftpAuthPubKey returned ===");
            const std::string status = std::format("PubKey: rc={} auth={} pw=0x{:x}", rc, auth, auth_pw);
            ShowStatus(status.c_str());
        }
        if (!triedPubkey)
            auth_pw &= ~SSH_AUTH_PUBKEY;
    }

    if (LogProc) LogProc(PluginNumber, MSGTYPE_DETAILS, "=== Auth section done ===");
    progress = 70; // PROG_AUTH_DONE
    if (auth != 0 || (auth_pw & SSH_AUTH_PUBKEY) == 0) {
        if (LogProc) LogProc(PluginNumber, MSGTYPE_DETAILS, "Trying password/keyboard auth fallback");
        const bool canKeyboardAuth = (auth_pw & SSH_AUTH_KEYBOARD) != 0;
        const bool canPasswordAuth = (auth_pw & SSH_AUTH_PASSWORD) != 0;
        const LoginSecretSplit storedSecret = SplitLoginSecret(ConnectSettings->password);
        const bool hasLoginPassword = !storedSecret.loginPassword.empty() &&
                                      (!ConnectSettings->key_passphrase_used || storedSecret.labelled);
        const bool preferPasswordFirst = !skipProbe && canPasswordAuth && hasLoginPassword;
        bool skippedKeyboardFirst = false;

        if (canKeyboardAuth && !preferPasswordFirst) {
            ShowStatusId(IDS_AUTH_KEYBDINT_FOR, ConnectSettings->user.c_str(), true);
            LoadStr(buf, IDS_AUTH_KEYBDINT);
            pConnectSettings cs = ConnectSettings;
            cs->InteractivePasswordSent = false;
            const SYSTICKS authStart = get_sys_ticks();
            int kbdIter = 0;
            while ((auth = cs->session->userauthKeyboardInteractive(cs->user.c_str(), (unsigned)cs->user.size(), &kbd_callback)) == LIBSSH2_ERROR_EAGAIN) {
                const int dirs = cs->session->blockDirections();
                const DWORD elapsed = (DWORD)get_ticks_between((std::max)(authStart, cs->authPromptDone));
                SFTP_LOG("AUTH", "kbd EAGAIN #%d dirs=0x%x elapsed=%u cbSent=%d", ++kbdIter, dirs, elapsed, cs->InteractivePasswordSent ? 1 : 0);
                if (ProgressLoop(buf.data(), progress, progress + 10, &loop, &lasttime))
                    break;
                if (elapsed > SSH_AUTH_STAGE_TIMEOUT_MS) {
                    ShowStatusId(IDS_LOG_KBD_AUTH_TIMEOUT, nullptr, true);
                    break;
                }
                WaitForSshIo(cs);
            }
            SFTP_LOG("AUTH", "kbd done auth=%d iters=%d cbSent=%d", auth, kbdIter, ConnectSettings->InteractivePasswordSent ? 1 : 0);
            CommitAuthPasswords(ConnectSettings, auth == 0);
            if (auth) {
                SftpLogLastError("libssh2_userauth_keyboard_interactive: ", auth);
                if ((auth_pw & SSH_AUTH_PASSWORD) == 0)
                    ShowErrorId(IDS_ERR_AUTH_KEYBDINT);
            }
        } else {
            auth = LIBSSH2_ERROR_INVAL;
            skippedKeyboardFirst = canKeyboardAuth;
        }

        // Do not resend a stored password that keyboard-interactive already had refused.
        bool storedRefused = auth != 0 && !skippedKeyboardFirst && canKeyboardAuth &&
                             ConnectSettings->InteractivePasswordSent;
        bool cancelled = false;

        if (auth != 0 && canPasswordAuth) {
            std::string passphrase = (!storedRefused && hasLoginPassword) ? storedSecret.loginPassword : std::string();
            struct WipePass {
                std::string& s;
                ~WipePass() {
                    if (!s.empty()) {
                        s.resize(s.capacity());
                        SecureZeroMemory(s.data(), s.size());
                        s.clear();
                    }
                }
            } wipePass{passphrase};
            bool typed = false;
            for (int typedTries = 0; ; ) {
                if (passphrase.empty()) {
                    if (typedTries >= 3)
                        break;
                    ++typedTries;
                    std::string title = std::format("SFTP password for {}@{}", ConnectSettings->user, ConnectSettings->server);
                    bool answered = false;
                    if (ConnectSettings->feedback) {
                        answered = ConnectSettings->feedback->RequestText(title, "", passphrase, true);
                    } else if (RequestProc) {
                        std::array<char, 256> tmpBuf{};
                        answered = RequestProc(PluginNumber, RT_Password, title.c_str(), nullptr, tmpBuf.data(), tmpBuf.size()-1) != 0;
                        if (answered)
                            passphrase = tmpBuf.data();
                        SecureZeroMemory(tmpBuf.data(), tmpBuf.size());
                    }
                    ConnectSettings->authPromptDone = get_sys_ticks();
                    if (!answered) {
                        auth = LIBSSH2_ERROR_AUTHENTICATION_FAILED;
                        cancelled = true;
                        break;
                    }
                    typed = true;
                }

                ShowStatusId(IDS_AUTH_PASSWORD_FOR, ConnectSettings->user.c_str(), true);
                LoadStr(buf, IDS_AUTH_PASSWORD);
                const SYSTICKS authStart = get_sys_ticks();
                int passIter = 0;
                // PASSWORD_EXPIRED is final when user cancels the change dialog — never re-enter libssh2.
                while (1) {
                    auth = ConnectSettings->session->userauthPassword(ConnectSettings->user.c_str(), (unsigned)ConnectSettings->user.size(), passphrase.c_str(), (unsigned)passphrase.length(), &newpassfunc);
                    if (auth != LIBSSH2_ERROR_EAGAIN)
                        break;
                    const int dirs = ConnectSettings->session->blockDirections();
                    const DWORD elapsed = (DWORD)get_ticks_between((std::max)(authStart, ConnectSettings->authPromptDone));
                    SFTP_LOG("AUTH", "pass EAGAIN #%d dirs=0x%x elapsed=%u", ++passIter, dirs, elapsed);
                    if (ProgressLoop(buf.data(), progress, progress + 10, &loop, &lasttime)) {
                        cancelled = true;
                        break;
                    }
                    if (elapsed > SSH_AUTH_STAGE_TIMEOUT_MS) {
                        ShowStatusId(IDS_LOG_PASS_AUTH_TIMEOUT, nullptr, true);
                        break;
                    }
                    WaitForSshIo(ConnectSettings);
                }
                SFTP_LOG("AUTH", "pass done auth=%d iters=%d", auth, passIter);
                if (auth == 0) {
                    if (ConnectSettings->password.empty())
                        ConnectSettings->password = passphrase;
                    break;
                }
                SftpLogLastError("libssh2_userauth_password_ex: ", auth);
                if (!typed)
                    storedRefused = true;
                passphrase.resize(passphrase.capacity());
                SecureZeroMemory(passphrase.data(), passphrase.size());
                passphrase.clear();
                if (cancelled || auth != LIBSSH2_ERROR_AUTHENTICATION_FAILED)
                    break;
            }
            if (auth && !cancelled) {
                if (!skippedKeyboardFirst)
                    ShowErrorId(IDS_ERR_AUTH_PASSWORD);
                else
                    ShowStatusId(IDS_ERR_AUTH_PASSWORD, nullptr, true);
            }
        }

        if (auth != 0 && skippedKeyboardFirst && !cancelled) {
            // Retry keyboard-interactive after password failure for servers that expose
            // both methods but only accept one depending on account policy.
            ShowStatusId(IDS_AUTH_KEYBDINT_FOR, ConnectSettings->user.c_str(), true);
            LoadStr(buf, IDS_AUTH_KEYBDINT);
            pConnectSettings cs = ConnectSettings;
            // Do not auto-resend a stored password already refused by password auth.
            cs->InteractivePasswordSent = storedRefused;
            const SYSTICKS authStart = get_sys_ticks();
            int kbdIter2 = 0;
            while ((auth = cs->session->userauthKeyboardInteractive(cs->user.c_str(), (unsigned)cs->user.size(), &kbd_callback)) == LIBSSH2_ERROR_EAGAIN) {
                const int dirs = cs->session->blockDirections();
                const DWORD elapsed = (DWORD)get_ticks_between((std::max)(authStart, cs->authPromptDone));
                SFTP_LOG("AUTH", "kbd2 EAGAIN #%d dirs=0x%x elapsed=%u cbSent=%d", ++kbdIter2, dirs, elapsed, cs->InteractivePasswordSent ? 1 : 0);
                if (ProgressLoop(buf.data(), progress, progress + 10, &loop, &lasttime))
                    break;
                if (elapsed > SSH_AUTH_STAGE_TIMEOUT_MS) {
                    ShowStatusId(IDS_LOG_KBD_AUTH_TIMEOUT, nullptr, true);
                    break;
                }
                WaitForSshIo(cs);
            }
            SFTP_LOG("AUTH", "kbd2 done auth=%d iters=%d cbSent=%d", auth, kbdIter2, ConnectSettings->InteractivePasswordSent ? 1 : 0);
            CommitAuthPasswords(ConnectSettings, auth == 0);
            if (auth) {
                SftpLogLastError("libssh2_userauth_keyboard_interactive: ", auth);
                ShowErrorId(IDS_ERR_AUTH_KEYBDINT);
            }
        }
    }

    const std::string authLog = std::format("Auth complete: auth={} auth_pw=0x{:x} scponly={}", auth, auth_pw, ConnectSettings->scponly);
    ShowStatus(authLog.c_str());
    SFTP_LOG("CONN", "%s", authLog.c_str());

    if (auth) {
        if (LogProc) {
            const std::string msg = std::format("SFTP: Authentication failed for '{}@{}'",
                ConnectSettings->user, ConnectSettings->server);
            LogProc(PluginNumber, MSGTYPE_IMPORTANTERROR, msg.c_str());
        }
        SFTP_LOG("CONN", "Auth failed, returning SFTP_FAILED");
        return SFTP_FAILED;
    }
    return 0;
}
