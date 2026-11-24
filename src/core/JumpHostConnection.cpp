// JumpHostConnection.cpp — SSH ProxyJump implementation.
// Connects to a jump host over TCP, authenticates, opens a direct-tcpip channel
// to the target host, and returns an ITransportStream wrapping that channel.
// The target SSH session then performs its own handshake over this stream.

#include "HostFingerprint.h"
#include "global.h"
#include <windows.h>
#include <ws2tcpip.h>
#include <algorithm>
#include <array>
#include <format>
#include <memory>
#include <string>

#include "JumpHostConnection.h"
#include "ProfileSettings.h"
#include "ITransportStream.h"
#include "ISshBackend.h"
#include "SftpClient.h"
#include "SftpInternal.h"
#include "PluginEntryPoints.h"
#include "CoreUtils.h"
#include "res/resource.h"

#include <libssh2/libssh2.h>
#include <libssh2/libssh2_sftp.h>

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// Minimal alloc/free callbacks for the jump session (same as main session).
static LPVOID jmp_alloc(size_t n, LPVOID* /*ab*/)   { return malloc(n); }
static LPVOID jmp_realloc(LPVOID p, size_t n, LPVOID* /*ab*/) { return realloc(p, n); }
static void   jmp_free(LPVOID p, LPVOID* /*ab*/)    { free(p); }

// Context threaded through the jump session abstract pointer for kbd-interactive.
struct JmpKbdCtx {
    pConnectSettings cs = nullptr;
    std::string user;
    std::string host;
    const char* password = nullptr;
    bool passwordSent = false;
    bool cancelled = false;
    SYSTICKS promptDone = 0;
};

static bool JumpPromptLooksLikePassword(const char* lower) noexcept
{
    if (!lower || !lower[0])
        return false;
    if (!strstr(lower, "password"))
        return false;
    if (strstr(lower, "oath") || strstr(lower, "otp") ||
        strstr(lower, "one time") || strstr(lower, "one-time") ||
        strstr(lower, "verification") || strstr(lower, "passcode") ||
        strstr(lower, "token") || strstr(lower, "new"))
        return false;
    return true;
}

// Keyboard-interactive callback for jump host: send the stored password at most
// once for a password prompt, and interactively prompt the user for 2FA/OTP or
// when no stored password applies.
extern "C" static void jmp_kbd_callback(
    LPCSTR name,   int name_len,
    LPCSTR instr,  int instr_len,
    int num_prompts,
    const LIBSSH2_USERAUTH_KBDINT_PROMPT* prompts,
    LIBSSH2_USERAUTH_KBDINT_RESPONSE* responses,
    LPVOID* abstract)
{
    auto* ctx = static_cast<JmpKbdCtx*>(*abstract);
    for (int i = 0; i < num_prompts; i++) {
        std::array<char, 256> lower{};
        const size_t copyLen = min(
            prompts ? static_cast<size_t>(prompts[i].length) : size_t{0},
            lower.size() - 1);
        if (copyLen > 0) memcpy(lower.data(), prompts[i].text, copyLen);
        lower[copyLen] = '\0';
        _strlwr_s(lower.data(), lower.size());

        const bool isPass = JumpPromptLooksLikePassword(lower.data());
        if (isPass && ctx && ctx->password && ctx->password[0] && !ctx->passwordSent) {
            ctx->passwordSent = true;
            responses[i].text   = _strdup(ctx->password);
            responses[i].length = responses[i].text ? static_cast<unsigned int>(strlen(responses[i].text)) : 0;
            continue;
        }

        std::string promptMsg;
        if (instr && instr_len > 0)
            promptMsg.assign(instr, static_cast<size_t>(instr_len));
        if (prompts && prompts[i].text && prompts[i].length > 0) {
            if (!promptMsg.empty()) promptMsg += "\n";
            promptMsg.append(reinterpret_cast<const char*>(prompts[i].text), prompts[i].length);
        }
        if (promptMsg.empty())
            promptMsg = "Password:";

        std::string title;
        if (name && name_len > 0)
            title.assign(name, static_cast<size_t>(name_len));
        else
            title = "Jump host";
        if (ctx && !ctx->host.empty())
            title += " " + ctx->user + "@" + ctx->host;

        std::string entered;
        bool answered = false;
        if (ctx && ctx->cs && ctx->cs->feedback) {
            answered = ctx->cs->feedback->RequestText(title, promptMsg, entered, true);
        } else if (RequestProc) {
            std::array<char, 256> buf{};
            answered = RequestProc(PluginNumber, RT_Password, title.c_str(), promptMsg.c_str(),
                                   buf.data(), buf.size() - 1) != 0;
            if (answered)
                entered = buf.data();
            SecureZeroMemory(buf.data(), buf.size());
        }
        if (ctx)
            ctx->promptDone = get_sys_ticks();
        if (answered) {
            responses[i].text   = _strdup(entered.c_str());
            responses[i].length = responses[i].text ? static_cast<unsigned int>(entered.size()) : 0;
        } else {
            if (ctx) ctx->cancelled = true;
            responses[i].text   = nullptr;
            responses[i].length = 0;
        }
        if (!entered.empty()) {
            entered.resize(entered.capacity());
            SecureZeroMemory(entered.data(), entered.size());
        }
    }
}

// ---------------------------------------------------------------------------
// Libssh2DirectTcpipStream
// ---------------------------------------------------------------------------
// ITransportStream implementation backed by a libssh2 direct-tcpip channel.
// The stream owns the jump ISshSession and ISshChannel.
// It does NOT own cs->sock — the caller (SftpCloseConnection / CleanupFailed)
// closes it via the normal socket teardown path.
// ---------------------------------------------------------------------------
class Libssh2DirectTcpipStream final : public ITransportStream {
public:
    Libssh2DirectTcpipStream(
        std::unique_ptr<ISshSession> session,
        std::unique_ptr<ISshChannel> channel,
        std::unique_ptr<JmpKbdCtx>   kbdCtx,
        SOCKET                       underlyingSocket)
        : kbdCtx_(std::move(kbdCtx))
        , session_(std::move(session))
        , channel_(std::move(channel))
        , sock_(underlyingSocket)
    {}

    ~Libssh2DirectTcpipStream() override { close(); }

    // ------------------------------------------------------------------
    // ITransportStream
    // ------------------------------------------------------------------

    ssize_t read(void* buf, size_t len) override
    {
        if (!channel_)
            return -1;
        ssize_t rc = channel_->read(static_cast<char*>(buf), len);
        if (rc == LIBSSH2_ERROR_EAGAIN)
            return ITRANSPORT_EAGAIN;
        return rc;
    }

    ssize_t write(const void* buf, size_t len) override
    {
        if (!channel_)
            return -1;
        ssize_t rc = channel_->write(static_cast<const char*>(buf), len);
        if (rc == LIBSSH2_ERROR_EAGAIN)
            return ITRANSPORT_EAGAIN;
        return rc;
    }

    bool waitReadable(DWORD timeoutMs) override
    {
        if (sock_ == INVALID_SOCKET)
            return false;
        // The channel data arrives on the jump TCP socket.
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sock_, &fds);
        struct timeval tv {};
        tv.tv_sec  = static_cast<long>(timeoutMs / 1000);
        tv.tv_usec = static_cast<long>((timeoutMs % 1000) * 1000);
        return select(0, &fds, nullptr, nullptr, &tv) > 0;
    }

    bool waitForSshIo(ISshSession* sess, DWORD timeoutMs) override
    {
        if (sock_ == INVALID_SOCKET)
            return false;
        const int dirs = sess ? sess->blockDirections() : 0;
        fd_set rfds, wfds;
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        // SSH control packets (including window updates) arrive on read even
        // when the nested target session reports an outbound block.
        FD_SET(sock_, &rfds);
        if (dirs & LIBSSH2_SESSION_BLOCK_OUTBOUND)
            FD_SET(sock_, &wfds);
        struct timeval tv {};
        tv.tv_sec = static_cast<long>(timeoutMs / 1000);
        tv.tv_usec = static_cast<long>((timeoutMs % 1000) * 1000);
        return select(0, &rfds, &wfds, nullptr, &tv) > 0;
    }

    const char* describe() const override { return desc_.c_str(); }

    void close() override
    {
        if (closed_)
            return;
        closed_ = true;

        // Close the direct-tcpip channel gracefully.
        if (channel_) {
            channel_->sendEof();
            channel_->channelClose();
            channel_->channelFree();
            channel_.reset();
        }

        // Disconnect the jump SSH session.
        if (session_) {
            // Non-blocking disconnect — best effort, ignore EAGAIN.
            for (int i = 0; i < 30; ++i) {
                int r = session_->disconnect("ProxyJump closed");
                if (r != LIBSSH2_ERROR_EAGAIN)
                    break;
                // Give the socket a tick to drain.
                fd_set fds; FD_ZERO(&fds); FD_SET(sock_, &fds);
                struct timeval tv { 0, 50000 };
                select(0, &fds, nullptr, nullptr, &tv);
            }
            session_->free();
            session_.reset();
        }
        // NOTE: sock_ is NOT closed here.
        // The caller (SftpCloseConnection / CleanupFailedConnect) does
        // closesocket(cs->sock) which IS sock_.
    }

    void setDescription(const std::string& d) { desc_ = d; }

private:
    std::unique_ptr<JmpKbdCtx>   kbdCtx_;
    std::unique_ptr<ISshSession> session_;
    std::unique_ptr<ISshChannel> channel_;
    SOCKET                       sock_   { INVALID_SOCKET };
    std::string                  desc_;
    bool                         closed_ { false };
};

// ---------------------------------------------------------------------------
// Internal: verify jump host fingerprint
// ---------------------------------------------------------------------------
// Returns true if fingerprint is accepted (unchanged or user approved).
// Updates jump.fingerprint and writes to INI on first-time / change.
static bool VerifyJumpFingerprint(
    pConnectSettings cs,
    ISshSession*     jmpSession,
    JumpHostSettings& jump)        // in/out: fingerprint field updated
{
    const std::string endpoint = jump.host + ":" + std::to_string(jump.port);
    std::array<char, 1024> savedEndpoint{};
    GetPrivateProfileString(cs->DisplayName.c_str(), "jumpfingerprinthost", "", savedEndpoint.data(),
                            static_cast<DWORD>(savedEndpoint.size()), cs->IniFileName.c_str());
    if (savedEndpoint[0] && endpoint != savedEndpoint.data()) return false;
    const std::string fp = Sha256HostFingerprint(jmpSession);
    if (fp.empty()) return false;
    if (MatchesLegacyFingerprint(jmpSession, jump.fingerprint)) {
        WritePrivateProfileString(cs->DisplayName.c_str(), "jumpfingerprint", fp.c_str(), cs->IniFileName.c_str());
        WritePrivateProfileString(cs->DisplayName.c_str(), "jumpfingerprinthost", endpoint.c_str(), cs->IniFileName.c_str());
        jump.fingerprint = fp;
    }
    ShowStatus(("Jump host fingerprint: " + fp).c_str());

    if (jump.fingerprint == fp)
        return true;   // known host, matches

    if (!jump.fingerprint.empty()) {
        if (cs->feedback) cs->feedback->ShowError("Jump host key changed. Verify the server before updating the saved fingerprint.");
        return false;
    }
    // First connection requires explicit acceptance.
    const bool firstTime = jump.fingerprint.empty();
    std::string msg = firstTime
        ? "First connection to jump host — fingerprint unknown.\nFingerprint: "
        : "Jump host fingerprint has CHANGED!\nNew fingerprint: ";
    msg += fp;
    msg += "\nAccept?";

    bool accepted = false;
    if (cs->feedback)
        accepted = cs->feedback->AskYesNo(msg.c_str(), "SSH ProxyJump Security Warning");

    if (!accepted)
        return false;

    // Persist to INI.
    WritePrivateProfileString(
        cs->DisplayName.c_str(), "jumpfingerprint",
        fp.c_str(), cs->IniFileName.c_str());
    WritePrivateProfileString(cs->DisplayName.c_str(), "jumpfingerprinthost", endpoint.c_str(), cs->IniFileName.c_str());
    jump.fingerprint = fp;
    return true;
}

// ---------------------------------------------------------------------------
// Internal: authenticate to jump host
// ---------------------------------------------------------------------------
static bool AuthJumpHost(
    pConnectSettings    cs,
    ISshSession*        jmpSession,
    const JumpHostSettings& jump,
    JmpKbdCtx*          kbdCtx,
    SOCKET              jmpSock,
    int&                progress,
    int&                loop,
    SYSTICKS&           lasttime,
    bool*               outCancelled)
{
    if (outCancelled)
        *outCancelled = false;
    // The jump session is non-blocking, so the first probe may need to wait
    // for the server's auth-method response.
    char* authList = nullptr;
    const SYSTICKS authProbeStart = get_sys_ticks();
    do {
        authList = jmpSession->userauthList(
            jump.user.c_str(), static_cast<unsigned>(jump.user.size()));
        if (authList)
            break;
        if (jmpSession->lastErrno() != LIBSSH2_ERROR_EAGAIN)
            break;
        if (get_ticks_between(authProbeStart) > SSH_PROBE_TIMEOUT_MS)
            break;
        if (ProgressLoop("Jump host: querying auth methods...",
                         progress, progress + 2, &loop, &lasttime)) {
            if (outCancelled) *outCancelled = true;
            return false;
        }
        IsSocketReadable(jmpSock);
    } while (true);

    if (!authList && jmpSession->userauthAuthenticated()) {
        ShowStatusId(IDS_LOG_JUMP_AUTH_NONE, nullptr, true);
        return true;
    }

    // If userauthList timed out / returned null, try all auth methods instead of Pageant only.
    const bool fallbackAll = (authList == nullptr);
    const bool canPassword = fallbackAll || strstr(authList, "password") != nullptr;
    const bool canPubkey   = fallbackAll || strstr(authList, "publickey") != nullptr;
    const bool canKbd      = fallbackAll || strstr(authList, "keyboard-interactive") != nullptr;

    ShowStatus(("Jump host auth methods: " + (authList ? std::string(authList) : "(all fallback)")).c_str());

    // --- 1. Agent auth ---
    if (jump.useagent && loadAgent) {
        ShowStatusId(IDS_LOG_JUMP_AGENT_TRY, nullptr, true);
        auto agent = jmpSession->agentInit();
        if (agent && agent->connect() == LIBSSH2_ERROR_NONE) {
            agent->listIdentities();
            struct libssh2_agent_publickey* prev = nullptr;
            struct libssh2_agent_publickey* id   = nullptr;
            while (agent->getIdentity(&id, prev) == 0) {
                int r = LIBSSH2_ERROR_EAGAIN;
                const SYSTICKS authStart = get_sys_ticks();
                while (r == LIBSSH2_ERROR_EAGAIN) {
                    r = agent->userauth(jump.user.c_str(), id);
                    if (r == LIBSSH2_ERROR_EAGAIN) {
                        if (get_ticks_between(authStart) > SSH_AUTH_STAGE_TIMEOUT_MS)
                            break;
                        IsSocketReadable(jmpSock);
                    }
                }
                if (r == LIBSSH2_ERROR_NONE) {
                    ShowStatusId(IDS_LOG_JUMP_AGENT_OK, nullptr, true);
                    agent->disconnect();
                    return true;
                }
                prev = id;
            }
            agent->disconnect();
        }
        ShowStatusId(IDS_LOG_JUMP_AGENT_FAIL, nullptr, true);
    }

    // --- 2. Public key auth ---
    if (canPubkey && !jump.privkeyfile.empty()) {
        ShowStatusId(IDS_LOG_JUMP_PUBKEY_TRY, nullptr, true);
        int r = LIBSSH2_ERROR_EAGAIN;
        const SYSTICKS authStart = get_sys_ticks();
        while (r == LIBSSH2_ERROR_EAGAIN) {
            r = jmpSession->userauthPubkeyFromFile(
                jump.user.c_str(),
                static_cast<unsigned>(jump.user.size()),
                jump.pubkeyfile.empty() ? nullptr : jump.pubkeyfile.c_str(),
                jump.privkeyfile.c_str(),
                jump.password.empty() ? nullptr : jump.password.c_str());
            if (r == LIBSSH2_ERROR_EAGAIN) {
                if (get_ticks_between(authStart) > SSH_AUTH_STAGE_TIMEOUT_MS)
                    break;
                IsSocketReadable(jmpSock);
            }
            if (ProgressLoop("Jump host: public key auth...", progress, progress + 5, &loop, &lasttime)) {
                if (outCancelled) *outCancelled = true;
                return false;
            }
        }
        if (r == LIBSSH2_ERROR_NONE) {
            ShowStatusId(IDS_LOG_JUMP_PUBKEY_OK, nullptr, true);
            return true;
        }
        ShowStatusId(IDS_LOG_JUMP_PUBKEY_FAIL, nullptr, true);
    }

    // --- 3. Password auth (stored once, then up to 3 typed tries) ---
    bool storedRefused = false;
    bool cancelled = false;
    if (canPassword) {
        std::string pass = !jump.password.empty() ? jump.password : cs->jump_entered_password;
        struct WipePass {
            std::string& s;
            ~WipePass() {
                if (!s.empty()) {
                    s.resize(s.capacity());
                    SecureZeroMemory(s.data(), s.size());
                    s.clear();
                }
            }
        } wipePass{pass};
        bool typed = false;
        for (int typedTries = 0; ; ) {
            if (pass.empty()) {
                if (typedTries >= 3)
                    break;
                ++typedTries;
                const std::string title = "Jump host password for " + jump.user + "@" + jump.host;
                bool answered = false;
                if (cs->feedback) {
                    answered = cs->feedback->RequestText(title, "", pass, true);
                } else if (RequestProc) {
                    std::array<char, 256> buf{};
                    answered = RequestProc(PluginNumber, RT_Password, title.c_str(), nullptr, buf.data(), buf.size() - 1) != 0;
                    if (answered)
                        pass = buf.data();
                    SecureZeroMemory(buf.data(), buf.size());
                }
                if (kbdCtx) kbdCtx->promptDone = get_sys_ticks();
                if (!answered) {
                    cancelled = true;
                    break;
                }
                typed = true;
            }
            ShowStatusId(IDS_LOG_JUMP_PASS_TRY, nullptr, true);
            int r = LIBSSH2_ERROR_EAGAIN;
            const SYSTICKS authStart = get_sys_ticks();
            while (r == LIBSSH2_ERROR_EAGAIN) {
                r = jmpSession->userauthPassword(
                    jump.user.c_str(), static_cast<unsigned>(jump.user.size()),
                    pass.c_str(), static_cast<unsigned>(pass.size()),
                    nullptr);
                if (r == LIBSSH2_ERROR_EAGAIN) {
                    if (get_ticks_between(authStart) > SSH_AUTH_STAGE_TIMEOUT_MS)
                        break;
                    IsSocketReadable(jmpSock);
                }
                if (ProgressLoop("Jump host: password auth...", progress, progress + 5, &loop, &lasttime)) {
                    cancelled = true;
                    break;
                }
            }
            if (r == LIBSSH2_ERROR_NONE) {
                if (typed)
                    cs->jump_entered_password = pass;
                ShowStatusId(IDS_LOG_JUMP_PASS_OK, nullptr, true);
                return true;
            }
            ShowStatusId(IDS_LOG_JUMP_PASS_FAIL, nullptr, true);
            if (!typed)
                storedRefused = true;
            pass.resize(pass.capacity());
            SecureZeroMemory(pass.data(), pass.size());
            pass.clear();
            if (cancelled || r != LIBSSH2_ERROR_AUTHENTICATION_FAILED)
                break;
        }
    }

    // --- 4. Keyboard-interactive (supports 2FA/OTP; never resends refused stored password) ---
    if (canKbd && !cancelled) {
        if (kbdCtx) {
            kbdCtx->passwordSent = storedRefused;
            kbdCtx->cancelled = false;
        }
        ShowStatusId(IDS_LOG_JUMP_KBD_TRY, nullptr, true);
        int r = LIBSSH2_ERROR_EAGAIN;
        const SYSTICKS authStart = get_sys_ticks();
        while (r == LIBSSH2_ERROR_EAGAIN) {
            r = jmpSession->userauthKeyboardInteractive(
                jump.user.c_str(), static_cast<unsigned>(jump.user.size()),
                jmp_kbd_callback);
            if (r == LIBSSH2_ERROR_EAGAIN) {
                const SYSTICKS since = kbdCtx ? (std::max)(authStart, kbdCtx->promptDone) : authStart;
                if (get_ticks_between(since) > SSH_AUTH_STAGE_TIMEOUT_MS)
                    break;
                IsSocketReadable(jmpSock);
            }
            if (ProgressLoop("Jump host: kbd-int auth...", progress, progress + 5, &loop, &lasttime)) {
                cancelled = true;
                break;
            }
        }
        if (kbdCtx && kbdCtx->cancelled)
            cancelled = true;
        if (r == LIBSSH2_ERROR_NONE) {
            ShowStatusId(IDS_LOG_JUMP_KBD_OK, nullptr, true);
            return true;
        }
        ShowStatusId(IDS_LOG_JUMP_KBD_FAIL, nullptr, true);
    }

    if (outCancelled)
        *outCancelled = cancelled;
    if (!cs->jump_entered_password.empty()) {
        cs->jump_entered_password.resize(cs->jump_entered_password.capacity());
        SecureZeroMemory(cs->jump_entered_password.data(), cs->jump_entered_password.size());
        cs->jump_entered_password.clear();
    }
    ShowStatusId(IDS_LOG_JUMP_AUTH_FAIL, nullptr, true);
    return false;
}

// ---------------------------------------------------------------------------
// ConnectViaJumpHost — public API
// ---------------------------------------------------------------------------
std::unique_ptr<ITransportStream> ConnectViaJumpHost(
    pConnectSettings          cs,
    JumpHostSettings&         jump,
    ISshBackend*              backend,
    const std::string&        targetHost,
    unsigned short            targetPort,
    int&                      progress,
    int&                      loop,
    SYSTICKS&                 lasttime)
{
    ShowStatusId(IDS_LOG_PROXYJUMP, nullptr, true);
    ShowStatus(("Jump host: " + jump.host + ":" + std::to_string(jump.port)).c_str());

    // Resolve jump password from TC password manager if stored under "!" sentinel.
    if (jump.password == "\001") {
        jump.password.clear();
        if (CryptProc && !cs->DisplayName.empty()) {
            std::array<char, 260> passBuf{};
            const std::string storeKey = JumpPasswordStoreName(cs->DisplayName);
            if (CryptProc(PluginNumber, CryptoNumber, FS_CRYPT_LOAD_PASSWORD,
                          storeKey.c_str(), passBuf.data(), static_cast<int>(passBuf.size() - 1)) == FS_FILE_OK) {
                jump.password = passBuf.data();
            }
            SecureZeroMemory(passBuf.data(), passBuf.size());
        }
    }

    // -----------------------------------------------------------------------
    // 1. TCP connect to jump host
    // -----------------------------------------------------------------------
    struct addrinfo hints{};
    hints.ai_family = (cs->protocoltype == 1) ? AF_INET :
                      (cs->protocoltype == 2) ? AF_INET6 : AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    const std::string portStr = std::to_string(jump.port);

    struct addrinfo* res = nullptr;
    if (getaddrinfo(jump.host.c_str(), portStr.c_str(), &hints, &res) != 0) {
        ShowStatus(("Jump host: DNS failed for " + jump.host).c_str());
        if (cs->feedback)
            cs->feedback->ShowError(("ProxyJump: cannot resolve jump host: " + jump.host).c_str());
        return nullptr;
    }

    SOCKET jmpSock = INVALID_SOCKET;
    bool connected = false;
    bool cancelledTcp = false;
    for (struct addrinfo* ai = res; ai && !connected && !cancelledTcp; ai = ai->ai_next) {
        if (jmpSock != INVALID_SOCKET) {
            closesocket(jmpSock);
            jmpSock = INVALID_SOCKET;
        }
        jmpSock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (jmpSock == INVALID_SOCKET)
            continue;

        SetBlockingSocket(jmpSock, false);
        if (connect(jmpSock, ai->ai_addr, static_cast<int>(ai->ai_addrlen)) == 0) {
            connected = true;
        } else if (WSAGetLastError() == WSAEWOULDBLOCK) {
            SYSTICKS t0 = get_sys_ticks();
            while (get_ticks_between(t0) < 15000) {
                if (IsSocketWritable(jmpSock)) {
                    int soErr = 0; int soLen = sizeof(soErr);
                    connected = getsockopt(jmpSock, SOL_SOCKET, SO_ERROR,
                                           reinterpret_cast<char*>(&soErr), &soLen) == 0 && soErr == 0;
                    break;
                }
                if (IsSocketError(jmpSock))    break;
                if (ProgressLoop("Connecting to jump host...", progress, progress + 5, &loop, &lasttime)) {
                    cancelledTcp = true;
                    break;
                }
            }
        }
    }
    freeaddrinfo(res);

    if (!connected) {
        if (jmpSock != INVALID_SOCKET)
            closesocket(jmpSock);
        if (!cancelledTcp) {
            ShowStatusId(IDS_LOG_JUMP_TCP_FAIL, jump.host.c_str(), true);
            if (cs->feedback)
                cs->feedback->ShowError(("ProxyJump: cannot connect to jump host: " + jump.host).c_str());
        }
        return nullptr;
    }
    ShowStatusId(IDS_LOG_JUMP_TCP_OK, jump.host.c_str(), true);

    // -----------------------------------------------------------------------
    // 2. Create jump SSH session
    // -----------------------------------------------------------------------
    // Keep kbd-interactive context on the heap so session->abstract never dangles.
    auto kbdCtx = std::make_unique<JmpKbdCtx>();
    kbdCtx->cs       = cs;
    kbdCtx->user     = jump.user;
    kbdCtx->host     = jump.host;
    kbdCtx->password = jump.password.c_str();

    auto jmpSession = backend->createSession(jmp_alloc, jmp_free, jmp_realloc, kbdCtx.get());
    if (!jmpSession) {
        closesocket(jmpSock);
        ShowStatusId(IDS_LOG_JUMP_SSH_FAIL, nullptr, true);
        if (cs->feedback)
            cs->feedback->ShowError(LngStrU8(IDS_ERR_JUMP_SESSION, "ProxyJump: libssh2 session init failed").c_str());
        return nullptr;
    }
    jmpSession->setBlocking(0);

    // SSH handshake with jump host.
    ShowStatusId(IDS_LOG_JUMP_HANDSHAKE, nullptr, true);
    {
        int r = LIBSSH2_ERROR_EAGAIN;
        bool cancelledHs = false;
        const ULONGLONG deadline = GetTickCount64() + 30000;
        while (r == LIBSSH2_ERROR_EAGAIN) {
            r = jmpSession->startup(static_cast<int>(jmpSock));
            if (r == LIBSSH2_ERROR_EAGAIN) {
                if (GetTickCount64() >= deadline) { r = LIBSSH2_ERROR_TIMEOUT; break; }
                IsSocketReadable(jmpSock);
            }
            if (ProgressLoop("Jump host: SSH handshake...", progress, progress + 5, &loop, &lasttime)) {
                cancelledHs = true;
                break;
            }
        }
        if (r != LIBSSH2_ERROR_NONE) {
            if (!cancelledHs) {
                char* msg = nullptr; int mlen = 0;
                jmpSession->lastError(&msg, &mlen, false);
                ShowStatusId(IDS_LOG_JUMP_HANDSHAKE_FAIL, msg ? msg : "unknown", true);
                if (cs->feedback)
                    cs->feedback->ShowError(("ProxyJump: jump host SSH handshake failed: " + (msg ? std::string(msg) : "")).c_str());
            }
            jmpSession->free();
            closesocket(jmpSock);
            return nullptr;
        }
    }
    ShowStatusId(IDS_LOG_JUMP_HANDSHAKE_OK, nullptr, true);

    // -----------------------------------------------------------------------
    // 3. Verify jump host fingerprint
    // -----------------------------------------------------------------------
    if (!VerifyJumpFingerprint(cs, jmpSession.get(), jump)) {
        jmpSession->disconnect("fingerprint rejected");
        jmpSession->free();
        closesocket(jmpSock);
        ShowStatusId(IDS_LOG_JUMP_FP_REJECTED, nullptr, true);
        return nullptr;
    }

    // -----------------------------------------------------------------------
    // 4. Authenticate to jump host
    // -----------------------------------------------------------------------
    ShowStatus(("Jump host: authenticating as " + jump.user + "...").c_str());
    bool authCancelled = false;
    if (!AuthJumpHost(cs, jmpSession.get(), jump, kbdCtx.get(), jmpSock, progress, loop, lasttime, &authCancelled)) {
        kbdCtx->password = nullptr;
        jmpSession->disconnect("auth failed");
        jmpSession->free();
        closesocket(jmpSock);
        if (!authCancelled && cs->feedback)
            cs->feedback->ShowError(("ProxyJump: authentication to jump host failed.\nUser: " + jump.user).c_str());
        return nullptr;
    }
    kbdCtx->password = nullptr;

    // -----------------------------------------------------------------------
    // 5. Open direct-tcpip channel to target
    // -----------------------------------------------------------------------
    ShowStatus(("Jump host: opening tunnel to " + targetHost + ":" + std::to_string(targetPort) + "...").c_str());

    std::unique_ptr<ISshChannel> channel;
    {
        // non-blocking open: retry on EAGAIN
        SYSTICKS t0 = get_sys_ticks();
        while (get_ticks_between(t0) < 15000) {
            channel = jmpSession->directTcpip(
                targetHost.c_str(), static_cast<int>(targetPort),
                "127.0.0.1", 0);
            if (channel)
                break;
            // check if it's EAGAIN
            if (LIBSSH2_ERROR_EAGAIN != jmpSession->lastErrno())
                break;
            IsSocketReadable(jmpSock);
            if (ProgressLoop("Jump host: opening tunnel...", progress, progress + 5, &loop, &lasttime))
                break;
        }
    }

    if (!channel) {
        char* msg = nullptr; int mlen = 0;
        jmpSession->lastError(&msg, &mlen, false);
        ShowStatus(("Jump host: direct-tcpip failed to " + targetHost + ": " + (msg ? msg : "unknown")).c_str());
        if (cs->feedback)
            cs->feedback->ShowError(("ProxyJump: cannot open tunnel to " + targetHost + ":" + std::to_string(targetPort) + "\n" + (msg ? msg : "")).c_str());
        jmpSession->disconnect("direct-tcpip failed");
        jmpSession->free();
        closesocket(jmpSock);
        return nullptr;
    }

    ShowStatus(("Jump host: tunnel open to " + targetHost + ":" + std::to_string(targetPort)).c_str());

    // -----------------------------------------------------------------------
    // 6. Build transport stream
    // -----------------------------------------------------------------------
    // Store jump socket in cs->sock so IsSocketReadable() works for the
    // target SSH session startup loops.
    cs->sock = jmpSock;

    auto stream = std::make_unique<Libssh2DirectTcpipStream>(
        std::move(jmpSession),
        std::move(channel),
        std::move(kbdCtx),
        jmpSock);
    stream->setDescription("direct-tcpip:" + targetHost + ":" + std::to_string(targetPort)
                           + "@" + jump.host);

    return stream;
}
