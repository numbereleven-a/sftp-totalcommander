#include "global.h"
#include "SftpInternal.h"
#include "Libssh2Backend.h"
#include "PluginEntryPointsInternal.h"
#include "ScpTransfer.h"
#include "TransferUtils.h"
#include "PhpAgentClient.h"
#include "PhpRequestSigning.h"
#include "IUserFeedback.h"
#include "ProxyNegotiator.h"
#include "ServerRegistry.h"
#include "CoreUtils.h"
#include "ProfileSettings.h"
#include "core/KittyDecrypt.h"
#include "IsolatedAppData.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <vector>
// Includes the production import boundary so portable sources can be tested
// without consulting the user's installed SSH clients or registry sessions.
#include "../src/core/SessionImport.cpp"

namespace {
int failures = 0;
std::string response = "synthetic-pass";
void check(bool ok, const char* label) {
    std::cout << (ok ? "PASS " : "FAIL ") << label << std::endl;
    if (!ok) ++failures;
}
int WINAPI progress(int, LPCSTR, LPCSTR, int) { return 0; }
void WINAPI logMessage(int, int, LPCSTR) {}
BOOL WINAPI request(int, int type, LPCSTR, LPCSTR, LPSTR result, int length) {
    if (type == RT_Password && result) { strlcpy(result, response.c_str(), length); return TRUE; }
    return FALSE;
}
int WINAPI progressW(int, LPCWSTR, LPCWSTR, int percent) { return percent; }
void WINAPI logW(int, int, LPCWSTR) {}
BOOL WINAPI requestW(int, int type, LPCWSTR, LPCWSTR, LPWSTR result, int length) {
    if (type == RT_Password && result) {
        const std::wstring value(response.begin(), response.end());
        wcsncpy_s(result, length, value.c_str(), _TRUNCATE);
        return TRUE;
    }
    return FALSE;
}
void terminalControls() {
    for (const auto& [input, expected] : std::initializer_list<std::pair<const char*, const char*>>{
        {"\x1b[31mred\x1b[0m text", "red text"},
        {"\x1b[?2004hfilename.bin", "filename.bin"},
        {"\x1b]3008;context\x07" "filename.bin", "filename.bin"},
        {"\x1b]0;title\x1b\\filename.bin", "filename.bin"},
        {"\x1bPprivate\x1b\\filename.bin", "filename.bin"},
        {"\x1b(Bfilename.bin", "filename.bin"},
        {"\x1b[?2004h\xD0\xB8\xD0\xBC\xD1\x8F.bin", "\xD0\xB8\xD0\xBC\xD1\x8F.bin"},
        {"plain \\141.bin", "plain a.bin"}}) {
        std::string text(input);
        StripEscapeSequences(text.data());
        check(text.c_str() == std::string(expected), "terminal control filter preserves payload");
    }

    // Long >8 KiB line handling via std::string StripEscapeSequences overload.
    std::string longLine = "\x1b[31m" + std::string(10000, 'x') + "\x1b[0m";
    StripEscapeSequences(longLine);
    check(longLine.size() == 10000 && longLine == std::string(10000, 'x'),
          "long line escape filtering preserves >8 KiB payload");

    // UnixTimeToLocalTime must equal FileTimeToLocalFileTime(utc).
    {
        const time_t t = 1700000000;
        FILETIME got{}, expUtc{}, expLocal{};
        ConvUnixTimeToFileTime(&expUtc, t);
        FileTimeToLocalFileTime(&expUtc, &expLocal);
        const bool convOk = UnixTimeToLocalTime(&t, &got);
        check(convOk && got.dwLowDateTime == expLocal.dwLowDateTime &&
              got.dwHighDateTime == expLocal.dwHighDateTime,
              "UnixTimeToLocalTime applies local timezone offset once");
    }

    // CopyMoveServerInIniW must copy sections exceeding 1024 WCHARs of key names.
    {
        std::array<WCHAR, MAX_PATH> tmpDir{};
        GetTempPathW(static_cast<DWORD>(tmpDir.size()), tmpDir.data());
        const auto iniPath = std::filesystem::path(tmpDir.data()) /
            ("sftp_ini_copy_" + std::to_string(GetCurrentProcessId()) + ".ini");
        std::filesystem::remove(iniPath);
        for (int i = 0; i < 200; ++i) {
            const std::wstring k = L"key_" + std::to_wstring(i);
            const std::wstring v = L"val_" + std::to_wstring(i);
            WritePrivateProfileStringW(L"src_sec", k.c_str(), v.c_str(), iniPath.c_str());
        }
        const int copyRc = CopyMoveServerInIniW("src_sec", "dst_sec", false, true, iniPath.c_str());
        std::array<WCHAR, 64> readVal{};
        GetPrivateProfileStringW(L"dst_sec", L"key_199", L"", readVal.data(), static_cast<DWORD>(readVal.size()), iniPath.c_str());
        std::filesystem::remove(iniPath);
        check(copyRc == 0 && wcscmp(readVal.data(), L"val_199") == 0,
              "CopyMoveServerInIniW preserves >1024-char sections");
    }

    // SOCKS5 numeric IPv6 wire format and ATYP=3 domain length >= 128 (over IPv4 loopback mock).
    {
        WSADATA wsa{};
        WSAStartup(MAKEWORD(2, 2), &wsa);

        auto startLoopbackMock = [&](auto serverHandler) {
            SOCKET srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            sockaddr_in sa{}; sa.sin_family = AF_INET;
            sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            bind(srv, reinterpret_cast<sockaddr*>(&sa), sizeof(sa));
            int slen = sizeof(sa);
            getsockname(srv, reinterpret_cast<sockaddr*>(&sa), &slen);
            listen(srv, 1);
            std::thread worker([srv, serverHandler]() mutable {
                SOCKET c = accept(srv, nullptr, nullptr);
                if (c != INVALID_SOCKET) {
                    serverHandler(c);
                    closesocket(c);
                }
                closesocket(srv);
            });
            SOCKET cli = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            connect(cli, reinterpret_cast<sockaddr*>(&sa), sizeof(sa));
            return std::pair<SOCKET, std::thread>(cli, std::move(worker));
        };

        // 1) IPv6 CONNECT wire format: VER=5 CMD=1 RSV=0 ATYP=4 <16-byte IPv6> <port>
        std::vector<unsigned char> reqWire;
        {
            auto [cli, worker] = startLoopbackMock([&](SOCKET c) {
                char hello[16]{};
                recv(c, hello, 3, 0);
                const char method[2] = { 0x05, 0x00 };
                send(c, method, 2, 0);
                char req[64]{};
                int n = recv(c, req, sizeof(req), 0);
                if (n > 0) reqWire.assign(reinterpret_cast<unsigned char*>(req), reinterpret_cast<unsigned char*>(req) + n);
                const unsigned char rep[10] = { 0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 22 };
                send(c, reinterpret_cast<const char*>(rep), sizeof(rep), 0);
            });
            tConnectSettings cs{};
            cs.sock = cli;
            cs.server = "2001:db8::1";
            cs.customport = 22;
            int loop = 0; SYSTICKS lasttime = 0;
            const int rc = SftpConnectProxySocks5(&cs, 22, "socks5", 0, &loop, &lasttime);
            closesocket(cli);
            worker.join();
            check(rc == 0 && reqWire.size() == 22 &&
                  reqWire[0] == 0x05 && reqWire[1] == 0x01 &&
                  reqWire[2] == 0x00 && reqWire[3] == 0x04 &&
                  reqWire[4] == 0x20 && reqWire[5] == 0x01 &&
                  reqWire[19] == 0x01 && reqWire[20] == 0x00 && reqWire[21] == 0x16,
                  "SOCKS5 numeric IPv6 encodes 22-byte CONNECT request");
        }

        // 2) ATYP=3 domain length 130 (>= 128 unsigned byte).
        {
            auto [cli, worker] = startLoopbackMock([&](SOCKET c) {
                char hello[16]{};
                recv(c, hello, 3, 0);
                const char method[2] = { 0x05, 0x00 };
                send(c, method, 2, 0);
                char req[64]{};
                recv(c, req, sizeof(req), 0);
                std::vector<unsigned char> rep(4 + 1 + 130 + 2, 'a');
                rep[0] = 0x05; rep[1] = 0x00; rep[2] = 0x00; rep[3] = 0x03;
                rep[4] = 130;
                rep[rep.size() - 2] = 0x00; rep[rep.size() - 1] = 0x16;
                send(c, reinterpret_cast<const char*>(rep.data()), static_cast<int>(rep.size()), 0);
            });
            tConnectSettings cs{};
            cs.sock = cli;
            cs.server = "127.0.0.1";
            int loop = 0; SYSTICKS lasttime = 0;
            const int rc = SftpConnectProxySocks5(&cs, 22, "socks5", 0, &loop, &lasttime);
            closesocket(cli);
            worker.join();
            check(rc == 0, "SOCKS5 ATYP=3 domain length >= 128 decodes as unsigned");
        }

        // 3) myrecv returns 0 immediately on peer EOF instead of spinning until timeout.
        {
            auto [cli, worker] = startLoopbackMock([](SOCKET c) {
                shutdown(c, SD_SEND);
            });
            SetBlockingSocket(cli, false);
            char buf[16]{};
            int loop = 0;
            SYSTICKS last = get_sys_ticks();
            const auto t0 = std::chrono::steady_clock::now();
            const int rc = myrecv(cli, buf, sizeof(buf), 0, "recv", 0, &loop, &last);
            const auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - t0).count();
            closesocket(cli);
            worker.join();
            check(rc == 0 && elapsedMs < 2000, "myrecv returns 0 promptly on peer EOF");
        }
        WSACleanup();
    }

    // Shell safety, random markers, split echo, and remote entry name filtering.
    {
        check(ShellCommandIsSafe("/home/user/file name-1.txt") &&
              !ShellCommandIsSafe("/home/user/bad\nname") &&
              !ShellCommandIsSafe("/home/user/bad\x1bname") &&
              !ShellCommandIsSafe("/home/user/bad\x7fname"),
              "ShellCommandIsSafe rejects control characters");

        const std::string m1 = ShellMarker("__WFX_TEST__");
        const std::string m2 = ShellMarker("__WFX_TEST__");
        const std::string echoCmd = ShellEchoMarker(m1);
        check(m1 != m2 && m1.size() > 20 &&
              echoCmd.find(m1) == std::string::npos &&
              echoCmd.find("\"\"") != std::string::npos,
              "ShellMarker is randomized and ShellEchoMarker splits marker literal");

        check(RemoteEntryNameIsSafeW(L"normal file.txt") &&
              !RemoteEntryNameIsSafeW(L"") &&
              !RemoteEntryNameIsSafeW(L"dir\\evil.txt") &&
              !RemoteEntryNameIsSafeW(L"dir/evil.txt") &&
              !RemoteEntryNameIsSafeW(L"ctrl\x01name"),
              "RemoteEntryNameIsSafeW rejects path separators and control chars");
    }

    // Local filename sanitization (invalid chars, trailing dot/space, Windows reserved devices).
    {
        auto sanitize = [](std::wstring p) {
            SanitizeLocalFileNameW(p.data());
            return p;
        };
        check(sanitize(L"C:\\dir\\a<b>c.txt") == L"C:\\dir\\a_b_c.txt" &&
              sanitize(L"C:\\dir\\trail.") == L"C:\\dir\\trail_" &&
              sanitize(L"C:\\dir\\space ") == L"C:\\dir\\space_" &&
              sanitize(L"C:\\dir\\CON") == L"C:\\dir\\CO_" &&
              sanitize(L"C:\\dir\\nul.txt") == L"C:\\dir\\nu_.txt" &&
              sanitize(L"C:\\dir\\COM1.log") == L"C:\\dir\\COM_.log" &&
              sanitize(L"C:\\dir\\LPT9") == L"C:\\dir\\LPT_" &&
              sanitize(L"C:\\dir\\normal.txt") == L"C:\\dir\\normal.txt",
              "SanitizeLocalFileNameW neutralizes unsafe chars and Windows device names");
    }

    // Long path (> 260 chars) end-to-end test via CreateDirectoryT / CreateFileT /
    // GetFileAttributesExT / MoveFileExT / DeleteFileT.
    {
        std::array<WCHAR, MAX_PATH> tmpDir{};
        GetTempPathW(static_cast<DWORD>(tmpDir.size()), tmpDir.data());
        std::wstring base = std::wstring(tmpDir.data()) + L"sftp_lp_" + std::to_wstring(GetCurrentProcessId());
        CreateDirectoryT(base.c_str(), nullptr);
        std::vector<std::wstring> dirs{base};
        std::wstring cur = base;
        for (int i = 0; i < 6; ++i) {
            cur += L"\\" + std::wstring(45, static_cast<wchar_t>(L'a' + i));
            CreateDirectoryT(cur.c_str(), nullptr);
            dirs.push_back(cur);
        }
        const std::wstring f1 = cur + L"\\staged_source.txt";
        const std::wstring f2 = cur + L"\\final_target.txt";
        HANDLE h = CreateFileT(f1.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        bool okCreate = (h != INVALID_HANDLE_VALUE);
        if (okCreate) {
            DWORD wr = 0;
            WriteFile(h, "longpath", 8, &wr, nullptr);
            CloseHandle(h);
        }
        WIN32_FILE_ATTRIBUTE_DATA attr1{};
        const bool okAttr1 = GetFileAttributesExT(f1.c_str(), &attr1) != 0 && attr1.nFileSizeLow == 8;
        const bool okMove = MoveFileExT(f1.c_str(), f2.c_str(), MOVEFILE_REPLACE_EXISTING) != 0;
        WIN32_FILE_ATTRIBUTE_DATA attr2{};
        const bool okAttr2 = GetFileAttributesExT(f2.c_str(), &attr2) != 0 && attr2.nFileSizeLow == 8;
        const bool okDel = DeleteFileT(f2.c_str()) != 0;
        for (auto it = dirs.rbegin(); it != dirs.rend(); ++it)
            RemoveDirectoryT(it->c_str());
        check(f2.size() > 260 && okCreate && okAttr1 && okMove && okAttr2 && okDel,
              "long-path *T file helpers create, stat, MoveFileExT, and delete >260-char paths");
    }

    // MimeEncodeData handles 1/2/3-byte tail lengths without reading past input end.
    {
        char out[32]{};
        const char d1[1] = {'M'};
        const char d2[2] = {'M', 'a'};
        const char d3[3] = {'M', 'a', 'n'};
        MimeEncodeData(d1, 1, out, sizeof(out));
        const bool ok1 = (std::string(out) == "TQ==");
        MimeEncodeData(d2, 2, out, sizeof(out));
        const bool ok2 = (std::string(out) == "TWE=");
        MimeEncodeData(d3, 3, out, sizeof(out));
        const bool ok3 = (std::string(out) == "TWFu");
        check(ok1 && ok2 && ok3, "MimeEncodeData encodes 1/2/3-byte groups accurately");
    }

    // KittyDecrypt rejects wrong-key garbage via printable ASCII check.
    {
        std::string plain;
        // 32 hex chars (16 random-looking ciphertext bytes) with wrong host/termtype must fail LooksTyped().
        const bool decWrong = DecryptKittyPassword("00112233445566778899aabbccddeeff", "wrong.invalid", "xterm", plain);
        check(!decWrong && plain.empty(), "KittyDecrypt rejects control-byte garbage on wrong key");
    }

    // ProfileSettings: dynamic INI reads (> MAX_PATH), useagent=1 keeps password,
    // invalid filemod/dirmod fallback, jumppassword=! sets jump_cryptpass.
    {
        std::array<char, MAX_PATH> tmpDir{};
        GetTempPathA(static_cast<DWORD>(tmpDir.size()), tmpDir.data());
        const std::string ini = std::string(tmpDir.data()) + "sftp_prof_test_" + std::to_string(GetCurrentProcessId()) + ".ini";
        DeleteFileA(ini.c_str());

        const std::string longCmd = "/usr/libexec/" + std::string(310, 's') + "/sftp-server";
        std::array<char, 512> encPw{};
        EncryptString("kept-secret", encPw.data(), static_cast<UINT>(encPw.size()));
        WritePrivateProfileStringA("prof1", "server", "example.invalid", ini.c_str());
        WritePrivateProfileStringA("prof1", "user", "alice", ini.c_str());
        WritePrivateProfileStringA("prof1", "useagent", "1", ini.c_str());
        WritePrivateProfileStringA("prof1", "password", encPw.data(), ini.c_str());
        WritePrivateProfileStringA("prof1", "sftpservercommand", longCmd.c_str(), ini.c_str());
        WritePrivateProfileStringA("prof1", "filemod", "badmode", ini.c_str());
        WritePrivateProfileStringA("prof1", "dirmod", "999", ini.c_str());
        WritePrivateProfileStringA("prof1", "usejumphost", "1", ini.c_str());
        WritePrivateProfileStringA("prof1", "jumphost", "bastion.invalid", ini.c_str());
        WritePrivateProfileStringA("prof1", "jumppassword", "!", ini.c_str());

        tConnectSettings loaded{};
        const bool ok = LoadServerSettings("prof1", &loaded, ini.c_str());
        DeleteFileA(ini.c_str());
        check(ok &&
              loaded.sftpservercommand == longCmd &&
              loaded.useagent &&
              loaded.password == "kept-secret" &&
              loaded.filemod == 0644 &&
              loaded.dirmod == 0755 &&
              loaded.jump_cryptpass &&
              loaded.jump_password == "\001" &&
              JumpPasswordStoreName("prof1") == "prof1:jump",
              "LoadServerSettings supports >MAX_PATH fields, useagent+password, octal fallback, and jump cryptpass");
    }

    // Unsupported Proxy + Jump Host combination is explicitly refused instead of bypassing proxy.
    {
        FsInit(42, progress, logMessage, request);
        tConnectSettings combo{};
        combo.sock = INVALID_SOCKET;
        combo.server = "127.0.0.1";
        combo.customport = 22;
        combo.user = "synthetic";
        combo.proxynr = 1;
        combo.proxytype = sftp::Proxy::socks5;
        combo.proxyserver = "127.0.0.1:1080";
        combo.use_jump_host = true;
        combo.jump_host = "127.0.0.1";
        combo.jump_port = 2222;
        check(SftpConnect(&combo) == -26, "SftpConnect refuses unsupported Proxy + Jump Host combination");
    }
}
std::string readFile(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(file), {}};
}
void writeFile(const std::filesystem::path& path, const std::string& bytes) {
    std::ofstream file(path, std::ios::binary); file.write(bytes.data(), bytes.size());
}
tConnectSettings* connectTo(int port, const char* name, bool shell) {
    auto cs = std::make_unique<tConnectSettings>();
    cs->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(static_cast<u_short>(port));
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(cs->sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr))) throw std::runtime_error("connect failed");
    Libssh2Backend backend;
    cs->session = backend.createSession(nullptr, nullptr, nullptr, cs.get());
    cs->session->setBlocking(1);
    if (cs->session->startup(static_cast<int>(cs->sock))) throw std::runtime_error("handshake failed");
    if (cs->session->userauthPassword("synthetic", 9, "synthetic-pass", 14, nullptr)) throw std::runtime_error("auth failed");
    cs->session->setBlocking(0);
    SetBlockingSocket(cs->sock, false);
    cs->scponly = shell; cs->scpfordata = shell;
    cs->utf8names = 1; cs->unixlinebreaks = 0; cs->filemod = 0644; cs->dirmod = 0755;
    cs->server = "127.0.0.1"; cs->customport = static_cast<unsigned short>(port);
    cs->user = "synthetic"; cs->DisplayName = name;
    if (!shell) {
        const auto start = GetTickCount64();
        while (!(cs->sftpsession = cs->session->sftpInit())) {
            if (cs->session->lastErrno() != LIBSSH2_ERROR_EAGAIN || GetTickCount64() - start > 10000)
                throw std::runtime_error("SFTP init failed");
            WaitForSshIo(cs.get());
        }
    }
    if (!SetServerIdForName(name, cs.get())) throw std::runtime_error("registration failed");
    return cs.release();
}
void authPrompts() {
    tConnectSettings cs{};
    void* context = &cs;
    LIBSSH2_USERAUTH_KBDINT_RESPONSE result{};
    LIBSSH2_USERAUTH_KBDINT_PROMPT prompt{};
    std::string text = "Verification code:";
    prompt.text = reinterpret_cast<unsigned char*>(text.data()); prompt.length = static_cast<unsigned>(text.size());
    response = "synthetic-code";
    kbd_callback(nullptr, 0, nullptr, 0, 1, &prompt, &result, &context);
    check(cs.password.empty() && result.text && response == result.text, "OTP answer is sent but not retained as a password");
    free(result.text);
    for (const char* label : {"Passcode:", "OTP password:", "One-time password:"}) {
        text = label; prompt.text = reinterpret_cast<unsigned char*>(text.data()); prompt.length = static_cast<unsigned>(text.size());
        kbd_callback(nullptr, 0, nullptr, 0, 1, &prompt, &result, &context);
        check(cs.password.empty(), label);
        free(result.text);
    }
    text = "Password:"; prompt.text = reinterpret_cast<unsigned char*>(text.data()); prompt.length = static_cast<unsigned>(text.size());
    response = "synthetic-pass";
    kbd_callback(nullptr, 0, nullptr, 0, 1, &prompt, &result, &context);
    check(cs.password.empty() && cs.typed_password == response && result.text && response == result.text,
          "typed keyboard-interactive password is held until login succeeds");
    free(result.text);

    // "New password:" must never auto-send stored password and stores typed value in changed_password.
    {
        tConnectSettings ncs{};
        ncs.password = "old-secret";
        void* nctx = &ncs;
        std::string newPrompt = "New password:";
        prompt.text = reinterpret_cast<unsigned char*>(newPrompt.data());
        prompt.length = static_cast<unsigned>(newPrompt.size());
        response = "new-secret";
        kbd_callback(nullptr, 0, nullptr, 0, 1, &prompt, &result, &nctx);
        check(result.text && std::string(result.text) == "new-secret" &&
              ncs.changed_password == "new-secret" && ncs.password == "old-secret",
              "New password prompt never auto-sends stored secret and captures changed_password");
        free(result.text);
    }

    // When unlabelled stored password unlocked a key, do not reuse it as login password.
    {
        tConnectSettings kcs{};
        kcs.password = "key-only-pass";
        kcs.key_passphrase_used = true;
        void* kctx = &kcs;
        text = "Password:";
        prompt.text = reinterpret_cast<unsigned char*>(text.data());
        prompt.length = static_cast<unsigned>(text.size());
        response = "account-pass";
        kbd_callback(nullptr, 0, nullptr, 0, 1, &prompt, &result, &kctx);
        check(result.text && std::string(result.text) == "account-pass" && kcs.typed_password == "account-pass",
              "key_passphrase_used prevents reusing unlabelled key passphrase for login");
        free(result.text);
    }

    tConnectSettings qcs{};
    qcs.password = "\"firstpw\",\"secondpw\"";
    qcs.key_passphrase_used = true;
    void* qctx = &qcs;
    kbd_callback(nullptr, 0, nullptr, 0, 1, &prompt, &result, &qctx);
    check(result.text && std::string(result.text) == "secondpw",
          "second quoted keyboard-interactive password strips delimiters");
    free(result.text);
}
void imports(const std::filesystem::path& root) {
    const auto input = (root / "portable.ini").string();
    const auto output = (root / "imported.ini").string();
    PortableSessionDescriptor descriptor{SessionSource::putty, input, "synthetic", "synthetic"};
    for (int mode = 0; mode != 3; ++mode) {
        writeFile(input, "[synthetic]\r\nHostName=example.invalid\r\nProxyMethod=" + std::to_string(mode == 1 ? 3 : 0) +
            "\r\nTunnel=" + std::to_string(mode == 2 ? 1 : 0) + "\r\n");
        WritePrivateProfileStringA(nullptr, nullptr, nullptr, input.c_str());
        bool unsupported = false;
        const bool ok = ImportPortableSessionToIni(descriptor, output.c_str(), unsupported, nullptr);
        check(mode == 0 ? ok && !unsupported : !ok && unsupported,
              mode == 0 ? "direct portable session imports" : mode == 1 ? "proxy import refuses a direct connection" : "tunnel import refuses a direct connection");
    }

    // IPv6 host + custom port wraps literal IPv6 in brackets, and TryAgent controls useagent (default 1).
    writeFile(input, "[ipv6sess]\r\nHostName=2001:db8::1\r\nPortNumber=2222\r\nTryAgent=0\r\n");
    WritePrivateProfileStringA(nullptr, nullptr, nullptr, input.c_str());
    PortableSessionDescriptor ipv6Desc{SessionSource::putty, input, "ipv6sess", "ipv6sess"};
    ImportedSessionData ipv6Data{};
    bool unsup6 = false;
    const bool ok6 = ImportPortableSessionToIni(ipv6Desc, output.c_str(), unsup6, &ipv6Data);
    const std::string srv6 = ::ReadIniString(ipv6Data.sectionName.c_str(), "server", "", output.c_str());
    const int agent6 = GetPrivateProfileIntA(ipv6Data.sectionName.c_str(), "useagent", 0, output.c_str());

    writeFile(input, "[agentdef]\r\nHostName=example.invalid\r\n");
    WritePrivateProfileStringA(nullptr, nullptr, nullptr, input.c_str());
    PortableSessionDescriptor defDesc{SessionSource::putty, input, "agentdef", "agentdef"};
    ImportedSessionData defData{};
    bool unsupDef = false;
    const bool okDef = ImportPortableSessionToIni(defDesc, output.c_str(), unsupDef, &defData);
    const int agentDef = GetPrivateProfileIntA(defData.sectionName.c_str(), "useagent", 0, output.c_str());

    check(ok6 && !unsup6 && srv6 == "[2001:db8::1]:2222" && agent6 == 0 && !ipv6Data.useagent &&
          okDef && !unsupDef && agentDef == 1 && defData.useagent,
          "session import brackets IPv6 host:port and honors TryAgent");
}
}

int wmain(int argc, wchar_t** argv) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    if (argc == 2) {
        IsolatedAppData isolated;
        if (std::wstring_view(argv[1]) == L"--terminal") terminalControls();
        else if (std::wstring_view(argv[1]) == L"--unicode-init") {
            FsInitW(42, progressW, logW, requestW);
            check(ProgressProc && LogProc && RequestProc, "Unicode-only initialization supplies ANSI bridges");
            authPrompts();
            check(ProgressProc(42, "source", "target", 37) == 37, "progress bridge preserves callback result");
        } else return 2;
        return failures ? 1 : 0;
    }
    if (argc != 3 && argc != 4) return 2;
    IsolatedAppData isolated;
    const std::filesystem::path root(argv[2]);
    FsInit(42, progress, logMessage, request);
    libssh2_init(0);
    authPrompts(); imports(root);
    auto* cs = connectTo(_wtoi(argv[1]), "synthetic", false);
    auto* other = connectTo(_wtoi(argv[1]), "other", false);
    const auto local = root / "local.bin", download = root / "download.bin";
    const std::string bytes = "alpha\r\nbeta\n";
    writeFile(local, bytes);
    check(SftpUploadFileW(cs, local.c_str(), L"/source.bin", false, false) == SFTP_OK, "SFTP upload completes");
    check(SftpDownloadFileW(cs, L"/source.bin", download.c_str(), true, bytes.size(), nullptr, false) == SFTP_OK && readFile(download) == bytes,
          "SFTP download preserves complete bytes");
    check(SftpChmodW(cs, L"\\source.bin", L"0750"), "Alt+A sets permissions through SFTP without a shell");
    LIBSSH2_SFTP_ATTRIBUTES attrs{};
    WaitForOperation([&] { return cs->sftpsession->stat("/source.bin", &attrs); }, 10000, cs);
    check((attrs.permissions & 07777) == 0750, "server received requested permissions");
    RemoteInfoStruct info{}; info.Size64 = bytes.size();
    check(FsRenMovFileW(L"\\synthetic\\source.bin", L"\\synthetic\\copy.bin", false, false, &info) == FS_FILE_OK &&
          SftpFileExistsW(cs, L"/source.bin") == 1, "same-session F5 copies and preserves the source");
    check(FsRenMovFileW(L"\\synthetic\\source.bin", L"\\other\\remote-copy.bin", false, false, &info) == FS_FILE_OK,
          "cross-session F5 relays a file");
    check(FsRenMovFileW(L"\\synthetic\\source.bin", L"\\other\\remote-copy.bin", true, false, &info) == FS_FILE_EXISTS &&
          SftpFileExistsW(cs, L"/source.bin") == 1, "cross-session move asks before overwrite and preserves the source");
    check(FsRenMovFileW(L"\\synthetic\\source.bin", L"\\other\\denied.bin", false, false, &info) == FS_FILE_WRITEERROR,
          "permission error is not treated as a missing destination");
    check(FsRenMovFileW(L"\\synthetic\\source.bin", L"\\other\\source.bin", true, true, &info) == FS_FILE_WRITEERROR,
          "two sessions cannot move a file onto itself");
    check(FsPutFileW(local.c_str(), L"\\synthetic\\move.bin", FS_COPYFLAGS_MOVE) == FS_FILE_OK && !std::filesystem::exists(local),
          "F6 upload removes the local source after completion");
    check(FsGetFileW(L"\\synthetic\\move.bin", const_cast<wchar_t*>(local.c_str()), FS_COPYFLAGS_MOVE, &info) == FS_FILE_OK &&
          readFile(local) == bytes && SftpFileExistsW(cs, L"/move.bin") == 0, "F6 download removes the remote source after completion");
    writeFile(download, bytes.substr(0, 3));
    check(FsGetFileW(L"\\synthetic\\source.bin", const_cast<wchar_t*>(download.c_str()), FS_COPYFLAGS_MOVE | FS_COPYFLAGS_RESUME, &info) == FS_FILE_OK &&
          readFile(download) == bytes && SftpFileExistsW(cs, L"/source.bin") == 1, "resumed move preserves the source");
    writeFile(local, "a");
    check(SftpUploadFileW(cs, local.c_str(), L"/source.bin", true, false) == SFTP_WRITEFAILED,
          "resume refuses a larger destination");
    cs->unixlinebreaks = 1;
    Global_TransferMode = 'A';
    check(SftpUploadFileW(cs, local.c_str(), L"/source.bin", true, false) == SFTP_WRITEFAILED,
          "text-mode resume refuses to truncate the destination");
    cs->unixlinebreaks = 0;
    Global_TransferMode = 'I';
    check(SftpDownloadFileW(cs, L"/short.bin", download.c_str(), true, 100, nullptr, false) != SFTP_OK,
          "truncated download is not successful");
    // Staged atomic overwrite: failed download onto pre-existing local file preserves original contents.
    {
        const auto keepPath = root / "keep_existing.bin";
        writeFile(keepPath, "original-content");
        const int dlRc = SftpDownloadFileW(cs, L"/definitely-missing.bin", keepPath.c_str(), true, 16, nullptr, false);
        info.Size64 = 16;
        const int fsRc = FsGetFileW(L"\\synthetic\\definitely-missing.bin", const_cast<wchar_t*>(keepPath.c_str()),
                                    FS_COPYFLAGS_OVERWRITE, &info);
        check(dlRc != SFTP_OK && fsRc == FS_FILE_READERROR && readFile(keepPath) == "original-content",
              "failed overwrite download preserves pre-existing local file");
    }
    // SFTP F6 rename with Overwrite=true onto an existing target succeeds via posix-rename/unlink fallback.
    {
        const auto r1 = root / "ren1.bin";
        const auto r2 = root / "ren2.bin";
        writeFile(r1, "new-payload");
        writeFile(r2, "old-payload");
        check(SftpUploadFileW(cs, r1.c_str(), L"/ren_src.bin", false, false) == SFTP_OK &&
              SftpUploadFileW(cs, r2.c_str(), L"/ren_dst.bin", false, false) == SFTP_OK &&
              SftpRenameMoveFileW(cs, L"/ren_src.bin", L"/ren_dst.bin", true, true, false) == SFTP_OK &&
              SftpFileExistsW(cs, L"/ren_src.bin") == 0 &&
              SftpDownloadFileW(cs, L"/ren_dst.bin", download.c_str(), true, 11, nullptr, false) == SFTP_OK &&
              readFile(download) == "new-payload",
              "SFTP rename with Overwrite replaces existing destination");
    }
    info.Size64 = 100;
    check(FsGetFileW(L"\\synthetic\\short.bin", const_cast<wchar_t*>(download.c_str()), FS_COPYFLAGS_OVERWRITE, &info) == FS_FILE_READERROR,
          "automatic resume stops when a retry adds no data");
    writeFile(local, bytes);
    HANDLE lock = CreateFileW(local.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    OVERLAPPED region{};
    const bool locked = LockFileEx(lock, LOCKFILE_EXCLUSIVE_LOCK, 0, 100, 0, &region) != 0;
    check(locked && FsPutFileW(local.c_str(), L"\\synthetic\\locked.bin", FS_COPYFLAGS_MOVE) == FS_FILE_READERROR && std::filesystem::exists(local),
          "local read failure preserves the F6 source");
    UnlockFileEx(lock, 0, 100, 0, &region); CloseHandle(lock);
    cs->scpfordata = true;
    check(SftpUploadFileW(cs, local.c_str(), L"/scp.bin", false, false) == SFTP_OK, "native SCP upload retries channel startup and receives completion");
    check(SftpDownloadFileW(cs, L"/scp.bin", download.c_str(), true, bytes.size(), nullptr, false) == SFTP_OK && readFile(download) == bytes,
          "native SCP download completes its handshake");
    check(SftpUploadFileW(cs, local.c_str(), L"/scp-fail.bin", false, false) == SFTP_WRITEFAILED, "SCP receiver disk error is reported");
    auto* shell = connectTo(_wtoi(argv[1]), "shell", true);
    const auto shellRoot = root / "shell";
    std::filesystem::create_directories(shellRoot / "nonempty");
    writeFile(shellRoot / "nonempty" / "keep.bin", bytes);
    check(SftpDeleteFileW(shell, (shellRoot / "nonempty").c_str(), true) == SFTP_FAILED &&
          std::filesystem::exists(shellRoot / "nonempty" / "keep.bin"), "shell rmdir preserves skipped files");
    std::filesystem::create_directory(shellRoot / "empty");
    check(SftpDeleteFileW(shell, (shellRoot / "empty").c_str(), true) == SFTP_OK && !std::filesystem::exists(shellRoot / "empty"),
          "shell rmdir reports actual success for an empty directory");
    check(SftpDeleteFileW(shell, L"/", true) == SFTP_FAILED && SftpDeleteFileW(shell, L"/a/..", true) == SFTP_FAILED,
          "shell deletion rejects root and dot paths");
    check(SftpCreateDirectoryW(shell, (shellRoot / "created").c_str()) == SFTP_OK && std::filesystem::is_directory(shellRoot / "created"),
          "shell mkdir uses the requested absolute path");
    check(SftpCreateDirectoryW(shell, (shellRoot / "missing" / "created").c_str()) == SFTP_FAILED,
          "shell mkdir reports a refused operation");
    const auto shellScp = shellRoot / "scp space.bin";
    check(SftpUploadFileW(shell, local.c_str(), shellScp.c_str(), false, false) == SFTP_OK && readFile(shellScp) == bytes,
          "shell SCP upload preserves a quoted absolute path");
    check(SftpDownloadFileW(shell, shellScp.c_str(), download.c_str(), true, bytes.size(), nullptr, false) == SFTP_OK && readFile(download) == bytes,
          "shell SCP download reads the header without an extra acknowledgement");
    writeFile(download, bytes.substr(0, 3));
    check(SftpDownloadFileW(shell, shellScp.c_str(), download.c_str(), true, bytes.size(), nullptr, true) == SFTP_OK && readFile(download) == bytes,
          "raw shell download resumes without losing bytes");
    writeFile(shellScp, bytes.substr(0, 3));
    check(SftpUploadFileW(shell, local.c_str(), shellScp.c_str(), true, false) == SFTP_OK && readFile(shellScp) == bytes,
          "raw shell upload resumes and checks completion");
    // Unreadable/missing remote file in raw shell fallback must fail AND not poison shell_dd_b64only.
    {
        shell->shell_transfer_force = false;
        shell->shell_transfer_dd = true;
        shell->shell_dd_b64only = false;
        int64_t ddLoaded = 0;
        const auto missFile = shellRoot / "no-such-shell-file.bin";
        HANDLE hTmp = CreateFileW(download.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        const int missRc = ShellDdDownloadFile(shell, ToRemotePathA(shell, missFile.c_str()), missFile.c_str(),
                                               hTmp, download.c_str(), 10, 0, &ddLoaded, false);
        CloseHandle(hTmp);
        check(missRc != SFTP_OK && !shell->shell_dd_b64only,
              "failed raw shell download reports error without poisoning shell_dd_b64only");
    }
    shell->shell_transfer_force = true; shell->shell_transfer_dd = true;
    const auto special = shellRoot / "space '; special.bin";
    check(SftpUploadFileW(shell, local.c_str(), special.c_str(), false, false) == SFTP_OK && readFile(special) == bytes,
          "shell base64 upload quotes names and verifies completion");
    check(SftpDownloadFileW(shell, special.c_str(), download.c_str(), true, bytes.size(), nullptr, false) == SFTP_OK && readFile(download) == bytes,
          "shell base64 download preserves complete bytes");
    check(SftpDownloadFileW(shell, special.c_str(), download.c_str(), true, -1, nullptr, false) == SFTP_OK && readFile(download) == bytes,
          "shell base64 download succeeds with unknown (-1) hinted size");
    check(SftpRenameMoveFileW(shell, special.c_str(), (shellRoot / "renamed.bin").c_str(), true, false, false) == SFTP_OK &&
          !std::filesystem::exists(special) && readFile(shellRoot / "renamed.bin") == bytes, "shell rename uses Unix paths and checks exit status");
    check(SftpUploadFileW(shell, local.c_str(), (shellRoot / "missing" / "failure.bin").c_str(), false, false) != SFTP_OK,
          "shell upload failure is not reported as success");
    std::string largeData(96 * 1024 + 7, '\0');
    for (size_t i = 0; i < largeData.size(); ++i) largeData[i] = static_cast<char>(i * 73);
    writeFile(local, largeData);
    const auto resumedLarge = shellRoot / "resumed-large.bin";
    writeFile(resumedLarge, largeData.substr(0, 2));
    check(SftpUploadFileW(shell, local.c_str(), resumedLarge.c_str(), true, false) == SFTP_OK && readFile(resumedLarge) == largeData,
          "multiline shell upload resumes at an exact byte offset across chunk boundaries");
    writeFile(local, bytes);
    if (argc == 4) {
        struct CountingFeedback : IUserFeedback {
            int errorDialogs = 0;
            void ShowError(const std::string&, const std::string&) override { ++errorDialogs; }
            void ShowMessage(const std::string&, const std::string&) override {}
            bool AskYesNo(const std::string&, const std::string&) override { return false; }
            bool RequestText(const std::string&, const std::string&, std::string&, bool) override { return false; }
        };
        auto* fb = new CountingFeedback();
        auto* php = new tConnectSettings{};
        php->transfermode = static_cast<int>(sftp::TransferMode::php_agent);
        php->server = "http://127.0.0.1:" + std::to_string(_wtoi(argv[3])) + "/sftp.php";
        php->password = "synthetic-pass";
        php->DisplayName = "php";
        php->feedback.reset(fb);
        SetServerIdForName("php", php);
        check(PhpAgentProbe(php) == SFTP_OK, "production PHP agent negotiation succeeds");
        check(SftpUploadFileW(php, local.c_str(), L"/source.bin", false, false) == SFTP_OK, "signed PHP upload succeeds");
        const auto emptyLocal = root / "empty.bin";
        const auto emptyDownload = root / "empty-dl.bin";
        writeFile(emptyLocal, "");
        check(SftpUploadFileW(php, emptyLocal.c_str(), L"/empty.bin", false, false) == SFTP_OK &&
              SftpFileExistsW(php, L"/empty.bin") == 1 &&
              SftpDownloadFileW(php, L"/empty.bin", emptyDownload.c_str(), true, 0, nullptr, false) == SFTP_OK &&
              readFile(emptyDownload).empty(),
              "PHP 0-byte upload and download succeed");
        check(SftpDownloadFileW(php, L"/does-not-exist.bin", download.c_str(), true, 10, nullptr, false) != SFTP_OK &&
              fb->errorDialogs == 0,
              "PHP transfer failure does not pop an extra modal dialog");
        check(SftpFileExistsW(php, L"/source.bin") == 1 && SftpFileExistsW(php, L"/missing.bin") == 0,
              "PHP destination probe distinguishes existing and missing files");
        info.Size64 = bytes.size();
        check(FsRenMovFileW(L"\\php\\source.bin", L"\\php\\copy.bin", false, false, &info) == FS_FILE_OK &&
              SftpFileExistsW(php, L"/source.bin") == 1, "PHP same-session copy preserves the source");
        php->php_tar = true;
        const auto batchA = root / "batchA.txt";
        const auto batchB = root / "batchB.txt";
        writeFile(batchA, "multi-dir-A");
        writeFile(batchB, "multi-dir-B");
        TarUploadSessionBegin(php);
        check(TarUploadSessionQueue(php, batchA.c_str(), "tdir1/batchA.txt") &&
              TarUploadSessionQueue(php, batchB.c_str(), "tdir2/batchB.txt") &&
              TarUploadSessionExecuteAndClear() == SFTP_OK &&
              SftpFileExistsW(php, L"/tdir1/batchA.txt") == 1 &&
              SftpFileExistsW(php, L"/tdir2/batchB.txt") == 1 &&
              SftpFileExistsW(php, L"/tdir1/tdir2/batchB.txt") == 0,
              "PHP TAR batch upload preserves distinct subdirectories");
        const auto dlBatchA = root / "dlBatchA.txt";
        const auto dlBatchB = root / "dlBatchB.txt";
        RemoteInfoStruct tarRi{};
        tarRi.Size64 = 11;
        TarDownloadSessionBegin(nullptr);
        check(FsGetFileW(L"\\php\\tdir1\\batchA.txt", const_cast<wchar_t*>(dlBatchA.c_str()), FS_COPYFLAGS_OVERWRITE, &tarRi) == FS_FILE_OK &&
              FsGetFileW(L"\\php\\tdir2\\batchB.txt", const_cast<wchar_t*>(dlBatchB.c_str()), FS_COPYFLAGS_OVERWRITE, &tarRi) == FS_FILE_OK &&
              TarDownloadSessionExecuteAndClear() == SFTP_OK &&
              readFile(dlBatchA) == "multi-dir-A" &&
              readFile(dlBatchB) == "multi-dir-B",
              "PHP TAR batch download adopts session for GET_MULTI_THREAD pattern");
        tConnectSettings freshAuth{};
        freshAuth.transfermode = static_cast<int>(sftp::TransferMode::php_agent);
        freshAuth.server = php->server;
        freshAuth.password = "synthetic-pass";
        std::string validateErr;
        check(PhpAgentValidateAuth(&freshAuth, validateErr) == SFTP_OK && freshAuth.php_auth_known,
              "PhpAgentValidateAuth auto-negotiates PROBE before LIST");
        php->password = "wrong-synthetic-pass";
        check(SftpFileExistsW(php, L"/missing.bin") == -1, "PHP authentication failure is not treated as a missing file");
        check(SftpUploadFileW(php, local.c_str(), L"/denied.bin", false, false) != SFTP_OK &&
              fb->errorDialogs == 0,
              "PHP upload auth failure logs without extra modal dialog");
        SetServerIdForName("php", nullptr);

        // Mock HTTP peers for outdated agent detection and Date header clock skew compensation.
        auto runHttpTestPeer = [](auto handler) {
            SOCKET listener = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            int len = sizeof(addr);
            ::bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
            ::listen(listener, 4);
            ::getsockname(listener, reinterpret_cast<sockaddr*>(&addr), &len);
            const uint16_t port = ntohs(addr.sin_port);
            auto stopFlag = std::make_shared<std::atomic<bool>>(false);
            std::thread worker([listener, handler, stopFlag] {
                while (!stopFlag->load(std::memory_order_relaxed)) {
                    fd_set set; FD_ZERO(&set); FD_SET(listener, &set);
                    timeval tv{0, 50000};
                    if (::select(0, &set, nullptr, nullptr, &tv) <= 0) continue;
                    SOCKET s = ::accept(listener, nullptr, nullptr);
                    if (s == INVALID_SOCKET) break;
                    std::string req;
                    char buf[1024];
                    while (req.find("\r\n\r\n") == std::string::npos) {
                        const int n = ::recv(s, buf, sizeof(buf), 0);
                        if (n <= 0) break;
                        req.append(buf, n);
                    }
                    const std::string resp = handler(req);
                    ::send(s, resp.data(), static_cast<int>(resp.size()), 0);
                    ::shutdown(s, SD_BOTH);
                    ::closesocket(s);
                }
            });
            struct PeerHandle {
                uint16_t port;
                SOCKET listener;
                std::shared_ptr<std::atomic<bool>> stop;
                std::thread worker;
                ~PeerHandle() {
                    stop->store(true, std::memory_order_relaxed);
                    ::closesocket(listener);
                    if (worker.joinable()) worker.join();
                }
            };
            return PeerHandle{port, listener, stopFlag, std::move(worker)};
        };

        {
            auto peer = runHttpTestPeer([](const std::string&) {
                const std::string body = R"({"ok":true,"capabilities":{"auth":{"signature_version":1,"hmac_auth":false}}})";
                return "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " +
                       std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
            });
            tConnectSettings oldAgent{};
            oldAgent.transfermode = static_cast<int>(sftp::TransferMode::php_agent);
            oldAgent.server = "http://127.0.0.1:" + std::to_string(peer.port) + "/sftp.php";
            oldAgent.password = "synthetic-pass";
            std::string probeErr, authErr;
            check(PhpAgentProbe(&oldAgent, &probeErr) != SFTP_OK && probeErr.find("sftp.php") != std::string::npos,
                  "outdated PHP agent is detected with actionable message");
            check(PhpAgentValidateAuth(&oldAgent, authErr) != SFTP_OK && authErr.find("sftp.php") != std::string::npos,
                  "PhpAgentValidateAuth surfaces outdated PHP agent error");
        }
        {
            // Future Date header (+3600s) must be applied to X-SFTP-TS and signed with the PROBE salt.
            const time_t skewed = std::time(nullptr) + 3600;
            std::tm gmt{};
            gmtime_s(&gmt, &skewed);
            static constexpr const char* kDays[] = {"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};
            static constexpr const char* kMonths[] = {"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};
            char dateBuf[64]{};
            snprintf(dateBuf, sizeof(dateBuf), "%s, %02d %s %04d %02d:%02d:%02d GMT",
                     kDays[gmt.tm_wday], gmt.tm_mday, kMonths[gmt.tm_mon],
                     gmt.tm_year + 1900, gmt.tm_hour, gmt.tm_min, gmt.tm_sec);
            const std::string dateHeader = dateBuf;
            bool probeUnsigned = false;
            bool listClockCompensated = false;
            bool listSaltMatched = false;
            auto peer = runHttpTestPeer([&](const std::string& req) {
                if (req.find("op=PROBE") != std::string::npos) {
                    probeUnsigned = (req.find("X-SFTP-SIGNATURE") == std::string::npos);
                    const std::string body = R"({"ok":true,"capabilities":{"recommended_chunk_size":1048576,"auth":{"signature_version":2,"hmac_auth":true,"salt":"skew-salt"}}})";
                    return "HTTP/1.1 200 OK\r\nDate: " + dateHeader +
                           "\r\nContent-Type: application/json\r\nContent-Length: " +
                           std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
                }
                auto getHdr = [&](const char* name) {
                    const std::string key = std::string(name) + ": ";
                    const size_t pos = req.find(key);
                    if (pos == std::string::npos) return std::string{};
                    const size_t end = req.find("\r\n", pos);
                    return req.substr(pos + key.size(), end - (pos + key.size()));
                };
                const std::string tsStr = getHdr("X-SFTP-TS");
                const std::string nonce = getHdr("X-SFTP-NONCE");
                const std::string sig = getHdr("X-SFTP-SIGNATURE");
                const long long sentTs = std::atoll(tsStr.c_str());
                listClockCompensated = (std::llabs(sentTs - static_cast<long long>(skewed)) <= 5);
                const std::string keyMat = "skew-salt:synthetic-pass";
                const std::string hmacKey = RequestDigest::memory(keyMat.data(), keyMat.size());
                const std::string emptyHash = RequestDigest::memory(nullptr, 0);
                const std::string base = "GET\nLIST\n/sftp.php?op=LIST&path=.&format=plain\n" +
                    tsStr + "\n" + nonce + "\n" + emptyHash;
                auto expectedMac = PhpHmacSha256(hmacKey, base);
                if (expectedMac) {
                    static constexpr char hex[] = "0123456789abcdef";
                    std::string expectedHex(expectedMac->size() * 2, '0');
                    for (size_t i = 0; i < expectedMac->size(); ++i) {
                        expectedHex[2 * i] = hex[(*expectedMac)[i] >> 4];
                        expectedHex[2 * i + 1] = hex[(*expectedMac)[i] & 15];
                    }
                    listSaltMatched = (sig == expectedHex);
                }
                return std::string("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            });
            tConnectSettings skewedAgent{};
            skewedAgent.transfermode = static_cast<int>(sftp::TransferMode::php_agent);
            skewedAgent.server = "http://127.0.0.1:" + std::to_string(peer.port) + "/sftp.php";
            skewedAgent.password = "synthetic-pass";
            std::string authErr;
            check(PhpAgentValidateAuth(&skewedAgent, authErr) == SFTP_OK &&
                  probeUnsigned && listClockCompensated && listSaltMatched,
                  "PROBE is unsigned and compensates server Date clock offset + salt");
        }
    }
    SetServerIdForName("shell", nullptr);
    SetServerIdForName("other", nullptr);
    SetServerIdForName("synthetic", nullptr);
    libssh2_exit();
    std::cout << "SSH integration: " << failures << " failures\n";
    return failures ? 1 : 0;
}
