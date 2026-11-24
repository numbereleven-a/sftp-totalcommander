#include "global.h"
#include <windows.h>
#include <array>
#include <format>
#include <vector>
#include "SftpClient.h"
#include "SftpInternal.h"
#include "ConnectionDialog.h"
#include "ProfileSettings.h"

namespace {

int ParseOctalMode(const std::string& text, int fallback) noexcept
{
    if (text.empty())
        return fallback;
    int value = 0;
    for (unsigned char ch : text) {
        if (ch < '0' || ch > '7')
            return fallback;
        value = (value << 3) | (ch - '0');
        if (value > 07777)
            return fallback;
    }
    return value;
}

} // namespace

std::string ReadIniString(LPCSTR section, LPCSTR key, LPCSTR defaultVal, LPCSTR iniFileName)
{
    if (!section || !key || !iniFileName)
        return defaultVal ? defaultVal : "";
    const LPCSTR def = defaultVal ? defaultVal : "";
    std::vector<char> buf(512, '\0');
    for (;;) {
        const DWORD got = GetPrivateProfileStringA(
            section, key, def, buf.data(), static_cast<DWORD>(buf.size()), iniFileName);
        if (got + 1 < buf.size() || buf.size() >= 65536)
            return std::string(buf.data(), got);
        buf.assign(buf.size() * 2, '\0');
    }
}

std::string JumpPasswordStoreName(const std::string& displayName)
{
    return displayName + ":jump";
}

bool LoadProxySettingsFromNr(int proxynr, pConnectSettings ConnectResults, LPCSTR iniFileName)
{
    if (proxynr > 0) {
        const std::string proxyentry = proxynr > 1 ? std::format("proxy{}", proxynr) : "proxy";
        ConnectResults->proxytype = sftp::Proxy::notused;
        int type = GetPrivateProfileInt(proxyentry.data(), "proxytype", -1, iniFileName);
        if (type >= 0)
            ConnectResults->proxytype = (sftp::Proxy)type;
        ConnectResults->proxyserver = ReadIniString(proxyentry.data(), "proxyserver", "", iniFileName);
        ConnectResults->proxyuser   = ReadIniString(proxyentry.data(), "proxyuser", "", iniFileName);
        std::array<char, 8192> szPassword{};
        if (GetPrivateProfileString(proxyentry.data(), "proxypassword", "", szPassword.data(), szPassword.size(), iniFileName)) {
            std::array<char, 4096> decPassword{};
            DecryptString(szPassword.data(), decPassword.data(), static_cast<UINT>(decPassword.size()));
            ConnectResults->proxypassword = decPassword.data();
            SecureZeroMemory(decPassword.data(), decPassword.size());
        } else
            ConnectResults->proxypassword.clear();
        SecureZeroMemory(szPassword.data(), szPassword.size());
        return (type != -1 || proxynr == 1);
    } else {
        ConnectResults->proxytype = sftp::Proxy::notused;
        ConnectResults->proxyserver.clear();
        ConnectResults->proxyuser.clear();
        ConnectResults->proxypassword.clear();
        return false;
    }
}

bool LoadServerSettings(LPCSTR DisplayName, pConnectSettings ConnectResults, LPCSTR iniFileName)
{
    std::array<char, 8192> szPassword{};
    ConnectResults->DisplayName = DisplayName ? DisplayName : "";
    ConnectResults->IniFileName = iniFileName ? iniFileName : "";
    // Plugin-wide SSH keepalive defaults.  Keepalive is deliberately off
    // unless explicitly enabled in [Configuration].
    ConnectResults->ssh_keepalive_enabled =
        GetPrivateProfileInt("Configuration", "keepalive", 0, iniFileName) != 0;
    const int keepaliveSeconds = GetPrivateProfileInt(
        "Configuration", "keepaliveinterval", 30, iniFileName);
    ConnectResults->ssh_keepalive_interval = static_cast<unsigned int>(
        keepaliveSeconds < 5 ? 5 : (keepaliveSeconds > 3600 ? 3600 : keepaliveSeconds));
    ConnectResults->ssh_keepalive_runtime = false;
    ConnectResults->ssh_keepalive_timer = 0;
    ConnectResults->ssh_keepalive_timer_thread = 0;
    ConnectResults->ssh_keepalive_timer_window = nullptr;
    ConnectResults->server = ReadIniString(DisplayName, "server", "", iniFileName);
    ConnectResults->protocoltype = GetPrivateProfileInt(DisplayName, "protocol", 0, iniFileName);
    ConnectResults->transfermode = GetPrivateProfileInt(DisplayName, "transfermode", 0, iniFileName);
    if (ConnectResults->transfermode < 0 || ConnectResults->transfermode > 3)
        ConnectResults->transfermode = 0;
    ConnectResults->user             = ReadIniString(DisplayName, "user", "", iniFileName);
    ConnectResults->savedfingerprint = ReadIniString(DisplayName, "fingerprint", "", iniFileName);
    ConnectResults->pubkeyfile       = ReadIniString(DisplayName, "pubkeyfile", "", iniFileName);
    ConnectResults->privkeyfile      = ReadIniString(DisplayName, "privkeyfile", "", iniFileName);
    ConnectResults->useagent = GetPrivateProfileInt(DisplayName, "useagent", 0, iniFileName) != 0;

    ConnectResults->filemod = ParseOctalMode(ReadIniString(DisplayName, "filemod", "644", iniFileName), 0644);
    ConnectResults->dirmod  = ParseOctalMode(ReadIniString(DisplayName, "dirmod", "755", iniFileName), 0755);

    ConnectResults->compressed = GetPrivateProfileInt(DisplayName, "compression", 0, iniFileName) != 0;
    ConnectResults->scpfordata = GetPrivateProfileInt(DisplayName, "scpfordata", 0, iniFileName) != 0;
    ConnectResults->scponly = GetPrivateProfileInt(DisplayName, "scponly", 0, iniFileName) != 0;
    if (ConnectResults->scponly)
        ConnectResults->scpfordata = true;
    ConnectResults->shell_transfer_dd = GetPrivateProfileInt(DisplayName, "shelltransfer", 0, iniFileName) != 0;
    ConnectResults->shell_transfer_force =
        GetPrivateProfileInt(DisplayName, "shelltransferforce",
                             ConnectResults->shell_transfer_dd ? 1 : 0,
                             iniFileName) != 0;
    ConnectResults->shell_dd_b64only  = false;
    ConnectResults->php_http_mode = GetPrivateProfileInt(DisplayName, "phphttpmode", 0, iniFileName);
    if (ConnectResults->php_http_mode < 0 || ConnectResults->php_http_mode > 2)
        ConnectResults->php_http_mode = 0;
    ConnectResults->php_chunk_mib = GetPrivateProfileInt(DisplayName, "phpchunkmb", 0, iniFileName);
    if (!(ConnectResults->php_chunk_mib == 0 || ConnectResults->php_chunk_mib == 1 ||
          ConnectResults->php_chunk_mib == 2 || ConnectResults->php_chunk_mib == 4 ||
          ConnectResults->php_chunk_mib == 8 || ConnectResults->php_chunk_mib == 16 ||
          ConnectResults->php_chunk_mib == 32 || ConnectResults->php_chunk_mib == 64))
        ConnectResults->php_chunk_mib = 0;
    ConnectResults->php_recommended_chunk_mib = 0;
    ConnectResults->php_agent_hmac = false;
    ConnectResults->php_tar = GetPrivateProfileInt(DisplayName, "phptar", 0, iniFileName) != 0;
    ConnectResults->lan_pair_root = ReadIniString(DisplayName, "lanpairroot", "", iniFileName);
    ConnectResults->lan_pair_role = GetPrivateProfileInt(DisplayName, "lanpairrole", 0, iniFileName);
    if (ConnectResults->lan_pair_role < 0 || ConnectResults->lan_pair_role > 2)
        ConnectResults->lan_pair_role = 0;
    ConnectResults->lan_pair_peer = ReadIniString(DisplayName, "lanpairpeer", "", iniFileName);
    ConnectResults->lan_pair_timeout_min = GetPrivateProfileInt(DisplayName, "lanpairtimeout", 0, iniFileName);
    if (ConnectResults->lan_pair_timeout_min < 0)
        ConnectResults->lan_pair_timeout_min = 0;
    ConnectResults->lan_pair_trusted_installer = GetPrivateProfileInt(DisplayName, "lanparti", 0, iniFileName) != 0;
    ConnectResults->trycustomlistcommand = 2;

    ConnectResults->detailedlog = GetPrivateProfileInt(DisplayName, "detailedlog", 0, iniFileName) != 0;
    ConnectResults->utf8names = GetPrivateProfileInt(DisplayName, "utf8", -1, iniFileName);
    ConnectResults->codepage = GetPrivateProfileInt(DisplayName, "codepage", 0, iniFileName);
    ConnectResults->unixlinebreaks = GetPrivateProfileInt(DisplayName, "unixlinebreaks", -1, iniFileName);
    ConnectResults->scpserver64bit = GetPrivateProfileInt(DisplayName, "largefilesupport", -1, iniFileName);
    ConnectResults->password.clear();
    ConnectResults->key_passphrase_used = false;
    // Always load saved password even when useagent is enabled, so key passphrases
    // and password fallbacks remain intact and saving the dialog does not erase them.
    if (GetPrivateProfileString(DisplayName, "password", "", szPassword.data(), szPassword.size(), iniFileName)) {
        if (strcmp(szPassword.data(), "!") == 0) {
            ConnectResults->password = "\001";
        } else {
            std::array<char, 4096> decPassword{};
            DecryptString(szPassword.data(), decPassword.data(), static_cast<UINT>(decPassword.size()));
            ConnectResults->password = decPassword.data();
            SecureZeroMemory(decPassword.data(), decPassword.size());
        }
        SecureZeroMemory(szPassword.data(), szPassword.size());
    }
    ConnectResults->proxynr = GetPrivateProfileInt(DisplayName, "proxynr", 0, iniFileName);

    LoadProxySettingsFromNr(ConnectResults->proxynr, ConnectResults, iniFileName);

    // -----------------------------------------------------------------------
    // Jump host (ProxyJump) settings
    // -----------------------------------------------------------------------
    ConnectResults->use_jump_host = GetPrivateProfileInt(DisplayName, "usejumphost", 0, iniFileName) != 0;
    {
        ConnectResults->jump_host        = ReadIniString(DisplayName, "jumphost", "", iniFileName);
        ConnectResults->jump_user        = ReadIniString(DisplayName, "jumpuser", "", iniFileName);
        ConnectResults->jump_pubkeyfile  = ReadIniString(DisplayName, "jumppubkeyfile", "", iniFileName);
        ConnectResults->jump_privkeyfile = ReadIniString(DisplayName, "jumpprivkeyfile", "", iniFileName);
        ConnectResults->jump_fingerprint = ReadIniString(DisplayName, "jumpfingerprint", "", iniFileName);
        const int rawJumpPort = GetPrivateProfileInt(DisplayName, "jumpport", 22, iniFileName);
        ConnectResults->jump_port = (rawJumpPort > 0 && rawJumpPort <= 65535)
            ? static_cast<unsigned short>(rawJumpPort) : 22;
        ConnectResults->jump_useagent    = GetPrivateProfileInt(DisplayName, "jumpuseagent", 0, iniFileName) != 0;
        ConnectResults->jump_cryptpass   = false;

        std::array<char, 8192> jumpPass{};
        if (GetPrivateProfileString(DisplayName, "jumppassword", "", jumpPass.data(), jumpPass.size(), iniFileName)) {
            if (strcmp(jumpPass.data(), "!") == 0) {
                ConnectResults->jump_password  = "\001";
                ConnectResults->jump_cryptpass = true;
            } else {
                std::array<char, 4096> decJumpPass{};
                DecryptString(jumpPass.data(), decJumpPass.data(), static_cast<UINT>(decJumpPass.size()));
                ConnectResults->jump_password = decJumpPass.data();
                SecureZeroMemory(decJumpPass.data(), decJumpPass.size());
            }
            SecureZeroMemory(jumpPass.data(), jumpPass.size());
        } else {
            ConnectResults->jump_password.clear();
        }
    }

    ConnectResults->neednewchannel = false;
    ConnectResults->connectsendcommand = ReadIniString(DisplayName, "sendcommand", "", iniFileName);
    ConnectResults->sftpservercommand  = ReadIniString(DisplayName, "sftpservercommand", "", iniFileName);
    ConnectResults->sendcommandmode = GetPrivateProfileInt(DisplayName, "sendcommandmode", 0, iniFileName);
    return !ConnectResults->server.empty();
}
