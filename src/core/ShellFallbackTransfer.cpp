#include "global.h"
#include <windows.h>
#include <array>
#include <memory>
#include <string>
#include <vector>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <atomic>
#include <span>
#include "SftpClient.h"
#include "PluginEntryPoints.h"
#include "SftpInternal.h"
#include "TransferUtils.h"
#include "ScpTransfer.h"
#include "ScpTransferInternal.h"
#include "res/resource.h"

// Keep command length safely below shell line limits on restricted hosts.
// 1024 bytes -> 1368 base64 chars (+ command overhead).
static constexpr size_t SHELL_DD_UPLOAD_CHUNK_BYTES  = 1024;
static constexpr size_t SHELL_DD_UPLOAD_LARGE_CHUNK = 48 * 1024;
static constexpr size_t SHELL_DD_DOWNLOAD_BLOCK      = 65536;

#define SHELL_DD_LOG(fmt, ...) SFTP_LOG("SHELL_DD", fmt, ##__VA_ARGS__)

// ---- minimal base64 helpers (no external dependency) ----
static constexpr std::string_view kB64Chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string ShellB64Encode(std::span<const uint8_t> data)
{
    std::string out;
    const size_t len = data.size();
    out.reserve(((len + 2) / 3) * 4 + 1);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t b = (uint32_t)data[i] << 16;
        if (i + 1 < len) b |= (uint32_t)data[i + 1] << 8;
        if (i + 2 < len) b |= (uint32_t)data[i + 2];
        out += kB64Chars[(b >> 18) & 0x3F];
        out += kB64Chars[(b >> 12) & 0x3F];
        out += (i + 1 < len) ? kB64Chars[(b >> 6) & 0x3F] : '=';
        out += (i + 2 < len) ? kB64Chars[b & 0x3F]        : '=';
    }
    return out;
}

static size_t ShellB64Decode(std::string_view in, std::span<uint8_t> out)
{
    // MimeDecode takes (const char*, size_t) and never calls strlen — no copy needed.
    return static_cast<size_t>(MimeDecode(in.data(), in.size(), out.data(), out.size()));
}

static std::string ShellNormalizeScpPath(const std::string& path)
{
    if (path.empty())
        return ".";
    return path;
}

static std::unique_ptr<ISshChannel> OpenShellDdChannel(pConnectSettings cs, const char* where)
{
    if (!cs || !cs->session)
        return {};

    for (int attempt = 0; attempt < 3; ++attempt) {
        auto raw = ConnectChannel(cs->session.get(), cs->sock);
        if (raw)
            return raw;

        SHELL_DD_LOG("%s: ConnectChannel failed (attempt %d/3)", where ? where : "ShellDd", attempt + 1);
        if (attempt == 0) {
            // First retry: give server a small window to close previous channel.
            Sleep(120);
        } else {
            // Next retries: force lightweight reconnect and retry.
            if (!ReconnectSFTPChannelIfNeeded(cs))
                break;
            Sleep(120);
        }
    }
    return {};
}

static bool ShellSendPersistentCommand(pConnectSettings cs, const std::string& command)
{
    if (!cs || !cs->scpShellChannel)
        return false;
    const size_t cmdLen = command.size();
    size_t written = 0;
    const SYSTICKS writeStart = get_sys_ticks();
    while (written < cmdLen) {
        int writeRc = cs->scpShellChannel->write(command.c_str() + written, cmdLen - written);
        if (writeRc > 0) {
            written += (size_t)writeRc;
            continue;
        }
        if (writeRc != LIBSSH2_ERROR_EAGAIN)
            return false;
        if (get_ticks_between(writeStart) > 15000)
            return false;
        if (cs->sock != INVALID_SOCKET)
            IsSocketReadable(cs->sock);
        else
            Sleep(25);
    }
    return true;
}

static const char* ShellTrimLeft(const char* p) noexcept
{
    while (p && *p && static_cast<unsigned char>(*p) <= 0x20)
        ++p;
    return p ? p : "";
}

static bool ShellIsEchoOrPromptLine(const char* line) noexcept
{
    const char* p = ShellTrimLeft(line);
    if (!p[0])
        return false;
    if (_strnicmp(p, "echo ", 5) == 0)
        return true;
    if (strstr(p, "$ echo ") != nullptr)
        return true;
    return false;
}

template <typename LineHandler>
static bool ShellExecPersistentProcessLines(
    pConnectSettings cs,
    const std::string& payload,
    DWORD timeoutMs,
    LineHandler onLine,
    int* outExitCode = nullptr)
{
    if (!cs)
        return false;
    if (!EnsureScpShell(cs))
        return false;
    if (!cs->scpShellChannel)
        return false;

    cs->scpShellMsgBuf.clear();
    cs->scpShellErrBuf.clear();

    // Per-command random markers + split-quote echo prevent prompt noise,
    // echoed commands, or file contents from spoofing command boundaries.
    const std::string beginMarker = ShellMarker("__WFX_DD_BEGIN__");
    const std::string endMarker = ShellMarker("__WFX_DD_END__");

    std::string fullCmd = ShellEchoMarker(beginMarker);
    fullCmd += "; ";
    fullCmd += payload;
    fullCmd += "; _rc=$?; ";
    fullCmd += ShellEchoMarker(endMarker);
    fullCmd += ":$_rc\n";

    if (!ShellSendPersistentCommand(cs, fullCmd)) {
        CloseScpShell(cs);
        return false;
    }

    SYSTICKS lastLine = get_sys_ticks();
    bool gotBeginMarker = false;
    bool gotEndMarker = false;
    int exitCode = -1;
    std::string line;

    for (;;) {
        if (!ReadChannelLine(cs->scpShellChannel.get(), line,
                             cs->scpShellMsgBuf, cs->scpShellErrBuf,
                             cs->sock, 1000, 1000)) {
            if (cs->scpShellChannel->eof() || EscapePressed() ||
                (cs->sock != INVALID_SOCKET && IsSocketError(cs->sock))) {
                break;
            }
            if (get_ticks_between(lastLine) > static_cast<int>(timeoutMs)) {
                break;
            }
            continue;
        }
        lastLine = get_sys_ticks();
        StripEscapeSequences(line);
        const char* p = ShellTrimLeft(line.c_str());
        if (!p[0])
            continue;

        if (!gotBeginMarker) {
            if (strcmp(p, beginMarker.c_str()) == 0) {
                gotBeginMarker = true;
                SFTP_LOG("SCP", "Detected BEGIN marker: %s", beginMarker.c_str());
            }
            continue;
        }

        // Prefer exact line-start marker matching; accept :<exitCode> suffix.
        if (!ShellIsEchoOrPromptLine(p) && strncmp(p, endMarker.c_str(), endMarker.size()) == 0) {
            const char* suffix = p + endMarker.size();
            if (suffix[0] == ':') {
                char* endp = nullptr;
                const long parsed = strtol(suffix + 1, &endp, 10);
                if (endp && endp != suffix + 1) {
                    exitCode = static_cast<int>(parsed);
                    gotEndMarker = true;
                }
            }
            break;
        }

        if (!onLine(p, strlen(p))) {
            CloseScpShell(cs);
            return false;
        }

        if (EscapePressed()) {
            CloseScpShell(cs);
            return false;
        }
    }
    if (!gotBeginMarker || !gotEndMarker) {
        CloseScpShell(cs);
        return false;
    }
    if (outExitCode) {
        *outExitCode = exitCode;
        return true;
    }
    return exitCode == 0;
}

static bool ShellExecPersistentCollectLines(
    pConnectSettings cs,
    const std::string& payload,
    std::vector<std::string>& outLines,
    int* outExitCode = nullptr)
{
    outLines.clear();
    return ShellExecPersistentProcessLines(cs, payload, 90000,
        [&](const char* p, size_t len) -> bool {
            outLines.emplace_back(p, len);
            return true;
        },
        outExitCode);
}

bool ShellRunPersistentCommand(
    pConnectSettings cs,
    const std::string& command,
    std::vector<std::string>& outLines,
    int* outExitCode)
{
    if (!cs || !ShellCommandIsSafe(command))
        return false;
    return ShellExecPersistentCollectLines(cs, command, outLines, outExitCode);
}

bool ShellSetRemoteMtime(pConnectSettings cs, const std::string& remotePath, long mtime)
{
    if (!cs || !cs->session || mtime <= 0)
        return false;
    const std::string normalizedPath = ShellNormalizeScpPath(remotePath);
    if (!ShellCommandIsSafe(normalizedPath))
        return false;

    const time_t t = static_cast<time_t>(mtime);
    struct tm utc{};
    if (gmtime_s(&utc, &t) != 0)
        return false;
    char stamp[32]{};
    _snprintf_s(stamp, sizeof(stamp), _TRUNCATE, "%04d%02d%02d%02d%02d.%02d",
                utc.tm_year + 1900, utc.tm_mon + 1, utc.tm_mday,
                utc.tm_hour, utc.tm_min, utc.tm_sec);
    std::string cmd = "TZ=UTC0 touch -m -c -t ";
    cmd += stamp;
    cmd += " -- '";
    cmd += string_util::ShellQuoteSingle(normalizedPath);
    cmd += "' 2>/dev/null";

    if (cs->shell_transfer_force || cs->shell_dd_b64only) {
        std::vector<std::string> lines;
        return ShellExecPersistentCollectLines(cs, cmd, lines);
    }

    auto ch = OpenShellDdChannel(cs, "ShellSetRemoteMtime");
    if (!ch) {
        std::vector<std::string> lines;
        return ShellExecPersistentCollectLines(cs, cmd, lines);
    }
    bool ok = SendChannelCommand(cs->session.get(), ch.get(), cmd.c_str(), cs->sock);
    if (ok) {
        const SYSTICKS waitStart = get_sys_ticks();
        char drain[256];
        while (!ch->eof()) {
            const int r = static_cast<int>(ch->read(drain, sizeof(drain)));
            if (r == LIBSSH2_ERROR_EAGAIN) {
                if (get_ticks_between(waitStart) > 5000 || EscapePressed())
                    break;
                ScpWaitIo(cs, false);
            } else if (r <= 0) {
                break;
            }
        }
        const int closeRc = WaitForOperation([&] { return ch->channelClose(); }, 5000, cs);
        ok = (closeRc == 0 && ch->getExitStatus() == 0);
    }
    DisconnectShell(ch.get());
    return ok;
}

// ---- helper: get remote file size via "wc -c" ----

static int64_t ShellGetRemoteFileSize(pConnectSettings cs, const std::string& remotePath)
{
    if (!cs || !cs->session)
        return -1;

    const std::string normalizedPath = ShellNormalizeScpPath(remotePath);
    if (!ShellCommandIsSafe(normalizedPath))
        return -1;
    std::string cmd = "wc -c < '" + string_util::ShellQuoteSingle(normalizedPath) + "' 2>/dev/null";

    auto parseOutput = [](const std::vector<std::string>& lines) -> int64_t {
        for (const auto& l : lines) {
            const char* p = l.c_str();
            while (*p == ' ' || *p == '\t') p++;
            if (*p >= '0' && *p <= '9') {
                return _atoi64(p);
            }
        }
        return -1;
    };

    // If shell fallback is forced or base64 fallback is active, use persistent shell
    // to bypass potential blocks on opening new exec channels.
    if (cs->shell_transfer_force || cs->shell_dd_b64only) {
        std::vector<std::string> lines;
        if (ShellExecPersistentCollectLines(cs, cmd, lines)) {
            return parseOutput(lines);
        }
        return -1;
    }

    std::unique_ptr<ISshChannel> ch = OpenShellDdChannel(cs, "ShellGetRemoteFileSize");
    if (!ch) {
        // Fallback to persistent shell if opening an exec channel fails.
        std::vector<std::string> lines;
        if (ShellExecPersistentCollectLines(cs, cmd, lines)) {
            return parseOutput(lines);
        }
        return -1;
    }

    if (!SendChannelCommand(cs->session.get(), ch.get(), cmd.c_str(), cs->sock)) {
        DisconnectShell(ch.get());
        return -1;
    }

    std::string msgbuf, errbuf;
    std::array<char, 256> line{};
    int64_t size = -1;
    while (ReadChannelLine(ch.get(), line.data(), line.size() - 1,
                           msgbuf, errbuf, cs->sock)) {
        StripEscapeSequences(line.data());
        const char* p = line.data();
        while (*p == ' ' || *p == '\t') p++;
        if (*p >= '0' && *p <= '9') {
            size = _atoi64(p);
            break;
        }
    }
    DisconnectShell(ch.get());
    return size;
}

// ---- raw binary download: exec "cat file" / "tail -c +N file" ----

static int ShellDdDownloadRaw(
    pConnectSettings cs,
    const std::string& remotePath,
    LPCWSTR remoteNameW,
    HANDLE localfile,
    LPCWSTR localNameW,
    int64_t hintedSize,
    int64_t resumeFrom,
    int64_t* outSizeLoaded,
    bool textMode)
{
    *outSizeLoaded = resumeFrom;

    // Build remote command. "tail -c +N" skips the first N-1 bytes.
    std::string cmd;
    const std::string normalizedPath = ShellNormalizeScpPath(remotePath);
    const std::string quotedPath = string_util::ShellQuoteSingle(normalizedPath);
    if (resumeFrom > 0) {
        char skipBuf[64];
        _snprintf_s(skipBuf, sizeof(skipBuf), _TRUNCATE, "%lld", (long long)(resumeFrom + 1));
        cmd = "tail -c +" + std::string(skipBuf) + " '" + quotedPath + "' 2>/dev/null";
    } else {
        cmd = "cat '" + quotedPath + "' 2>/dev/null";
    }

    std::unique_ptr<ISshChannel> ch = OpenShellDdChannel(cs, "ShellDdDownloadRaw");
    if (!ch)
        return SFTP_FAILED;

    // SendChannelCommand sends EOF so the remote process gets stdin-EOF.
    // We use SendChannelCommandNoEof here because we need to read stdout.
    if (!SendChannelCommandNoEof(cs->session.get(), ch.get(), cmd.c_str(), cs->sock)) {
        DisconnectShell(ch.get());
        return SFTP_READFAILED;
    }
    // Signal our side is done writing (we never write on a download).
    ch->sendEof();

    std::vector<char> buf(SHELL_DD_DOWNLOAD_BLOCK);
    DownloadTextFilter textFilter(textMode);
    std::vector<char> converted;
    const SYSTICKS starttime = get_sys_ticks();
    SYSTICKS lastIoTime = get_sys_ticks();

    while (true) {
        int rc = (int)ch->read(buf.data(), buf.size());
        if (rc > 0) {
            const char* writePtr = buf.data();
            size_t writeLen = static_cast<size_t>(rc);
            if (textMode) {
                converted.clear();
                writeLen = textFilter.Feed(buf.data(), static_cast<size_t>(rc), converted);
                writePtr = converted.data();
                textMode = textFilter.IsText();
            }
            if (writeLen > 0) {
                DWORD written = 0;
                if (!WriteFile(localfile, writePtr, static_cast<DWORD>(writeLen), &written, nullptr) ||
                    written != static_cast<DWORD>(writeLen)) {
                    DisconnectShell(ch.get());
                    return SFTP_WRITEFAILED;
                }
            }
            *outSizeLoaded += rc;
            lastIoTime = get_sys_ticks();
            int64_t totalForPct = (hintedSize > 0) ? hintedSize : *outSizeLoaded;
            if (UpdatePercentBar(cs, GetPercent(*outSizeLoaded, totalForPct), remoteNameW, localNameW)) {
                DisconnectShell(ch.get());
                return SFTP_ABORT;
            }
        } else if (rc == LIBSSH2_ERROR_EAGAIN) {
            if (EscapePressed()) {
                DisconnectShell(ch.get());
                return SFTP_ABORT;
            }
            if (get_ticks_between(lastIoTime) > (int)SFTP_SCP_READ_IDLE_TIMEOUT_MS) {
                SHELL_DD_LOG("raw download timeout after %lld bytes", (long long)*outSizeLoaded);
                DisconnectShell(ch.get());
                return SFTP_READFAILED;
            }
            ScpWaitIo(cs, false);
        } else if (rc == 0 || ch->eof()) {
            break; // clean EOF
        } else {
            SHELL_DD_LOG("raw download read error rc=%d", rc);
            DisconnectShell(ch.get());
            return SFTP_READFAILED;
        }
    }

    if (textMode) {
        converted.clear();
        const size_t tailLen = textFilter.Finish(converted);
        if (tailLen > 0) {
            DWORD written = 0;
            if (!WriteFile(localfile, converted.data(), static_cast<DWORD>(tailLen), &written, nullptr) ||
                written != static_cast<DWORD>(tailLen)) {
                DisconnectShell(ch.get());
                return SFTP_WRITEFAILED;
            }
        }
    }

    WaitForOperation([&] { return ch->waitEof(); }, 2000, cs);
    const int closeRc = WaitForOperation([&] { return ch->channelClose(); }, SFTP_SCP_READ_IDLE_TIMEOUT_MS, cs);
    const int exitStatus = ch->getExitStatus();
    DisconnectShell(ch.get());
    if (closeRc != 0 || exitStatus != 0) {
        SHELL_DD_LOG("raw download remote failed closeRc=%d exitStatus=%d", closeRc, exitStatus);
        return SFTP_READFAILED;
    }
    ShowTransferSpeedIfLarge("Shell-raw DL", *outSizeLoaded - resumeFrom, starttime);
    return SFTP_OK;
}

// ---- base64 download: exec "base64 file" ----

static int ShellDdDownloadBase64(
    pConnectSettings cs,
    const std::string& remotePath,
    LPCWSTR remoteNameW,
    HANDLE localfile,
    LPCWSTR localNameW,
    int64_t hintedSize,
    int64_t resumeFrom,
    int64_t* outSizeLoaded,
    bool textMode)
{
    *outSizeLoaded = resumeFrom;
    SHELL_DD_LOG("b64 DL start: path='%s' hinted=%lld resume=%lld",
                 remotePath.c_str(), (long long)hintedSize, (long long)resumeFrom);

    std::string payload;
    const std::string normalizedPath = ShellNormalizeScpPath(remotePath);
    const std::string quotedPath = string_util::ShellQuoteSingle(normalizedPath);
    if (resumeFrom > 0) {
        char skipBuf[64];
        _snprintf_s(skipBuf, sizeof(skipBuf), _TRUNCATE, "%lld", (long long)(resumeFrom + 1));
        payload = "test -r '";
        payload += quotedPath;
        payload += "' && tail -c +";
        payload += skipBuf;
        payload += " '";
        payload += quotedPath;
        payload += "' 2>/dev/null | base64";
    } else {
        payload = "base64 '";
        payload += quotedPath;
        payload += "' 2>/dev/null";
    }
    SHELL_DD_LOG("b64 DL payload: %s", payload.c_str());

    std::vector<uint8_t> decodeBuf(SHELL_DD_DOWNLOAD_BLOCK);
    DownloadTextFilter textFilter(textMode);
    std::vector<char> converted;
    const SYSTICKS starttime = get_sys_ticks();
    int lineCount = 0;    
    int64_t decodedTotal = resumeFrom;
    int streamRc = SFTP_OK;
    bool ok = ShellExecPersistentProcessLines(cs, payload, 90000,
        [&](const char* p, size_t lineLen) -> bool {
            lineCount++;
            if (lineLen > 0 && (lineCount <= 3 || (lineCount % 100) == 0)) {
                SHELL_DD_LOG("b64 DL line[%d] len=%llu", lineCount, (unsigned long long)lineLen);
            }
            if (lineLen == 0)
                return true;

            const size_t maxDecoded = (lineLen * 3) / 4 + 16;
            if (decodeBuf.size() < maxDecoded)
                decodeBuf.resize(maxDecoded);
            size_t decoded = ShellB64Decode(std::string_view(p, lineLen), std::span<uint8_t>(decodeBuf.data(), decodeBuf.size()));
            if (decoded == 0)
                return true;

            const char* writePtr = reinterpret_cast<const char*>(decodeBuf.data());
            size_t writeLen = decoded;
            if (textMode) {
                converted.clear();
                writeLen = textFilter.Feed(writePtr, decoded, converted);
                writePtr = converted.data();
                textMode = textFilter.IsText();
            }
            if (writeLen > 0) {
                DWORD written = 0;
                if (!WriteFile(localfile, writePtr, static_cast<DWORD>(writeLen), &written, nullptr) ||
                    written != static_cast<DWORD>(writeLen)) {
                    SHELL_DD_LOG("b64 DL write failed decoded=%llu written=%lu",
                                (unsigned long long)writeLen, (unsigned long)written);
                    streamRc = SFTP_WRITEFAILED;
                    return false;
                }
            }
            *outSizeLoaded += (int64_t)decoded;
            decodedTotal += (int64_t)decoded;

            int64_t totalForPct = (hintedSize > 0) ? hintedSize : *outSizeLoaded;
            if (UpdatePercentBar(cs, GetPercent(*outSizeLoaded, totalForPct), remoteNameW, localNameW)) {
                SHELL_DD_LOG("b64 DL aborted by user/progress");
                streamRc = SFTP_ABORT;
                return false;
            }
            if (EscapePressed()) {
                SHELL_DD_LOG("b64 DL aborted by escape");
                streamRc = SFTP_ABORT;
                return false;
            }
            return true;
        });
    if (!ok) {
        if (streamRc != SFTP_OK)
            return streamRc;
        SHELL_DD_LOG("b64 DL: persistent shell command failed");
        return SFTP_READFAILED;
    }
    if (textMode) {
        converted.clear();
        const size_t tailLen = textFilter.Finish(converted);
        if (tailLen > 0) {
            DWORD written = 0;
            if (!WriteFile(localfile, converted.data(), static_cast<DWORD>(tailLen), &written, nullptr) ||
                written != static_cast<DWORD>(tailLen)) {
                return SFTP_WRITEFAILED;
            }
        }
    }
    SHELL_DD_LOG("b64 DL end: lines=%d decodedTotal=%lld out=%lld",
                 lineCount, (long long)decodedTotal, (long long)*outSizeLoaded);

    if (hintedSize >= 0 && *outSizeLoaded != hintedSize) {
        SHELL_DD_LOG("b64 DL failed: size mismatch out=%lld hinted=%lld",
                     (long long)*outSizeLoaded, (long long)hintedSize);
        return SFTP_READFAILED;
    }

    ShowTransferSpeedIfLarge("Shell-b64 DL", *outSizeLoaded - resumeFrom, starttime);
    return SFTP_OK;
}

// ---- raw binary upload: exec "cat > file" or "cat >> file" ----

static int ShellDdUploadRaw(
    pConnectSettings cs,
    const std::string& remotePath,
    LPCWSTR remoteNameW,
    HANDLE localfile,
    LPCWSTR localNameW,
    int64_t fileSize,
    int64_t resumeFrom,
    int64_t* outSizeLoaded,
    bool textMode)
{
    *outSizeLoaded = resumeFrom;

    if (resumeFrom > 0) {
        LARGE_INTEGER li;
        li.QuadPart = resumeFrom;
        if (!SetFilePointerEx(localfile, li, nullptr, FILE_BEGIN))
            return SFTP_READFAILED;
    }

    // ">>" appends to existing file (resume); ">" creates/truncates.
    const std::string normalizedPath = ShellNormalizeScpPath(remotePath);
    const std::string quotedPath = string_util::ShellQuoteSingle(normalizedPath);
    std::string cmd = (resumeFrom > 0)
        ? "cat >> '" + quotedPath + "'"
        : "cat > '"  + quotedPath + "'";

    std::unique_ptr<ISshChannel> ch = OpenShellDdChannel(cs, "ShellDdUploadRaw");
    if (!ch)
        return SFTP_FAILED;

    // Do not send EOF yet; data must be written first.
    if (!SendChannelCommandNoEof(cs->session.get(), ch.get(), cmd.c_str(), cs->sock)) {
        DisconnectShell(ch.get());
        return SFTP_WRITEFAILED;
    }

    std::vector<char> buf(SHELL_DD_DOWNLOAD_BLOCK);
    std::vector<char> convBuf(textMode ? buf.size() + 16 : 0);
    bool pendingCr = false;
    const SYSTICKS starttime = get_sys_ticks();
    DWORD bytesRead = 0;

    while (ReadFile(localfile, buf.data(), (DWORD)buf.size(), &bytesRead, nullptr) && bytesRead > 0) {
        const char* sendPtr = buf.data();
        size_t sendLen = static_cast<size_t>(bytesRead);
        if (textMode) {
            sendLen = CrLfToLfStateful(buf.data(), bytesRead, convBuf.data(), pendingCr);
            sendPtr = convBuf.data();
        }
        if (sendLen > 0 && !ScpWriteAll(ch.get(), cs, sendPtr, sendLen, SFTP_SCP_WRITE_IDLE_TIMEOUT_MS)) {
            DisconnectShell(ch.get());
            return SFTP_WRITEFAILED;
        }
        *outSizeLoaded += bytesRead;
        if (UpdatePercentBar(cs, GetPercent(*outSizeLoaded, fileSize), localNameW, remoteNameW)) {
            DisconnectShell(ch.get());
            return SFTP_ABORT;
        }
        if (EscapePressed()) {
            DisconnectShell(ch.get());
            return SFTP_ABORT;
        }
    }
    if (textMode && pendingCr) {
        const char cr = '\r';
        if (!ScpWriteAll(ch.get(), cs, &cr, 1, SFTP_SCP_WRITE_IDLE_TIMEOUT_MS)) {
            DisconnectShell(ch.get());
            return SFTP_WRITEFAILED;
        }
    }

    // Signal EOF so the remote "cat" process exits and flushes its output.
    if (*outSizeLoaded != fileSize) {
        DisconnectShell(ch.get());
        return SFTP_READFAILED;
    }
    const SYSTICKS eofStart = get_sys_ticks();
    while (ch->sendEof() == LIBSSH2_ERROR_EAGAIN) {
        if (get_ticks_between(eofStart) > (int)SFTP_SCP_WRITE_IDLE_TIMEOUT_MS)
            break;
        ScpWaitIo(cs, true);
    }
    // Wait for remote cat to finish writing.
    const SYSTICKS waitStart = get_sys_ticks();
    while (!ch->eof()) {
        if (get_ticks_between(waitStart) > (int)SFTP_SCP_WRITE_IDLE_TIMEOUT_MS)
            break;
        if (EscapePressed())
            break;
        ScpWaitIo(cs, false);
    }

    const int closeRc = WaitForOperation([&] { return ch->channelClose(); }, SFTP_SCP_WRITE_IDLE_TIMEOUT_MS, cs);
    const bool complete = ch->eof() && closeRc == 0 && ch->getExitStatus() == 0;
    DisconnectShell(ch.get());
    if (!complete) return SFTP_WRITEFAILED;
    ShowTransferSpeedIfLarge("Shell-raw UL", *outSizeLoaded - resumeFrom, starttime);
    return SFTP_OK;
}

// ---- base64 upload: one command per chunk via printf | base64 -d ----

static bool ShellTakesMultiLineBase64(pConnectSettings cs)
{
    std::vector<std::string> output;
    if (!ShellExecPersistentCollectLines(cs, "printf '%s' 'QUJD\nREVG' | base64 -d | wc -c", output))
        return false;
    for (const auto& line : output) {
        const char* text = ShellTrimLeft(line.c_str());
        if (text[0] == '6' && (text[1] == '\0' || static_cast<unsigned char>(text[1]) <= ' '))
            return true;
    }
    return false;
}

static std::string ShellB64WrapLines(std::string_view encoded)
{
    std::string result;
    result.reserve(encoded.size() + encoded.size() / 76);
    for (size_t i = 0; i < encoded.size(); i += 76) {
        if (i) result += '\n';
        result.append(encoded.substr(i, 76));
    }
    return result;
}

static int ShellDdUploadBase64(
    pConnectSettings cs,
    const std::string& remotePath,
    LPCWSTR remoteNameW,
    HANDLE localfile,
    LPCWSTR localNameW,
    int64_t fileSize,
    int64_t expectedRemoteSize,
    int64_t resumeFrom,
    int64_t* outSizeLoaded,
    bool textMode)
{
    // Each chunk is decoded independently, so resume at the exact byte offset.
    int64_t alignedResume = resumeFrom;
    *outSizeLoaded = alignedResume;

    if (alignedResume > 0) {
        LARGE_INTEGER li;
        li.QuadPart = alignedResume;
        if (!SetFilePointerEx(localfile, li, nullptr, FILE_BEGIN))
            return SFTP_READFAILED;
    }

    bool firstChunk = (alignedResume == 0);
    const SYSTICKS starttime = get_sys_ticks();
    DWORD bytesRead = 0;

    if (!EnsureScpShell(cs) || !cs->scpShellChannel) {
        SHELL_DD_LOG("b64 UL: no persistent shell");
        return SFTP_FAILED;
    }

    const bool multiLine = fileSize - alignedResume > static_cast<int64_t>(SHELL_DD_UPLOAD_CHUNK_BYTES) &&
        ShellTakesMultiLineBase64(cs);
    const size_t chunkBytes = multiLine ? SHELL_DD_UPLOAD_LARGE_CHUNK : SHELL_DD_UPLOAD_CHUNK_BYTES;
    std::vector<uint8_t> readBuf(chunkBytes);
    std::vector<char> convBuf(textMode ? chunkBytes + 16 : 0);
    bool pendingCr = false;

    auto sendEncodedChunk = [&](const uint8_t* ptr, size_t len) -> bool {
        if (len == 0)
            return true;
        std::string b64 = ShellB64Encode(std::span<const uint8_t>(ptr, len));
        if (multiLine) b64 = ShellB64WrapLines(b64);

        // ">" truncates/creates on the first chunk; ">>" appends on all subsequent ones.
        const char* redirect = firstChunk ? ">" : ">>";
        firstChunk = false;

        // printf '%s' avoids echo interpreting backslash escapes or special chars.
        std::string cmd = "printf '%s' '" + b64 + "' | base64 -d ";
        cmd += redirect;
        cmd += " '";
        cmd += string_util::ShellQuoteSingle(ShellNormalizeScpPath(remotePath));
        cmd += "'";

        std::vector<std::string> cmdOut;
        return ShellExecPersistentCollectLines(cs, cmd, cmdOut);
    };

    while (ReadFile(localfile, readBuf.data(), static_cast<DWORD>(chunkBytes), &bytesRead, nullptr) && bytesRead > 0) {
        const uint8_t* payloadPtr = readBuf.data();
        size_t payloadLen = static_cast<size_t>(bytesRead);
        if (textMode) {
            payloadLen = CrLfToLfStateful(reinterpret_cast<const char*>(readBuf.data()), bytesRead, convBuf.data(), pendingCr);
            payloadPtr = reinterpret_cast<const uint8_t*>(convBuf.data());
        }
        if (!sendEncodedChunk(payloadPtr, payloadLen)) {
            SHELL_DD_LOG("b64 upload chunk failed at offset %lld", (long long)*outSizeLoaded);
            return SFTP_WRITEFAILED;
        }

        *outSizeLoaded += (int64_t)bytesRead;

        if (UpdatePercentBar(cs, GetPercent(*outSizeLoaded, fileSize), localNameW, remoteNameW)) {
            return SFTP_ABORT;
        }
        if (EscapePressed()) {
            return SFTP_ABORT;
        }
    }
    if (textMode && pendingCr) {
        const uint8_t cr = '\r';
        if (!sendEncodedChunk(&cr, 1))
            return SFTP_WRITEFAILED;
    }

    if (*outSizeLoaded != fileSize) return SFTP_READFAILED;
    if (firstChunk && alignedResume == 0) {
        std::vector<std::string> output;
        if (!ShellExecPersistentCollectLines(cs, ": > '" + string_util::ShellQuoteSingle(ShellNormalizeScpPath(remotePath)) + "'", output))
            return SFTP_WRITEFAILED;
    }
    const int64_t remoteSize = ShellGetRemoteFileSize(cs, remotePath);
    if (remoteSize >= 0 && remoteSize != expectedRemoteSize)
        return SFTP_WRITEFAILED;
    ShowTransferSpeedIfLarge("Shell-b64 UL", *outSizeLoaded - alignedResume, starttime);
    return SFTP_OK;
}

// ---- public entry points (called from SftpDownloadFileW / SftpUploadFileW) ----

int ShellDdDownloadFile(
    pConnectSettings cs,
    const std::string& remotePath,
    LPCWSTR remoteNameW,
    HANDLE localfile,
    LPCWSTR localNameW,
    int64_t hintedSize,
    int64_t resumeFrom,
    int64_t* outSizeLoaded,
    bool textMode)
{
    if (!cs || !cs->session || !IsValidFileHandle(localfile) || !outSizeLoaded)
        return SFTP_FAILED;
    if (!ShellCommandIsSafe(ShellNormalizeScpPath(remotePath)))
        return SFTP_READFAILED;

    // Forced mode uses the persistent interactive shell channel only.
    if (cs->shell_transfer_force) {
        cs->shell_dd_b64only = true;
        SHELL_DD_LOG("DL forced mode: using persistent shell base64 path");
    } else if (cs->scpShellChannel) {
        // Legacy non-forced mode may use exec channels for raw transfer.
        // Release persistent shell first on hosts with single-channel limits.
        SHELL_DD_LOG("DL closing persistent scpShellChannel before fallback transfer");
        CloseScpShell(cs);
    }

    ShowStatusId(IDS_LOG_SHELL_DL_START, nullptr, true);

    const int64_t startedAt = resumeFrom;
    auto rewindLocal = [&]() {
        LARGE_INTEGER pos{};
        pos.QuadPart = startedAt;
        SetFilePointerEx(localfile, pos, nullptr, FILE_BEGIN);
        SetEndOfFile(localfile);
        *outSizeLoaded = startedAt;
    };

    bool rawFailed = false;
    if (!cs->shell_dd_b64only) {
        int rc = ShellDdDownloadRaw(cs, remotePath, remoteNameW,
                                    localfile, localNameW, hintedSize, resumeFrom, outSizeLoaded, textMode);
        if (rc == SFTP_OK) {
            // Sanity-check size: if the raw channel mangled bytes the count will mismatch.
            if (hintedSize > 0 && *outSizeLoaded != hintedSize && startedAt == 0) {
                SHELL_DD_LOG("raw DL size mismatch: got %lld expected %lld, switching to base64",
                             (long long)*outSizeLoaded, (long long)hintedSize);
                rawFailed = true;
                rewindLocal();
            } else {
                return SFTP_OK;
            }
        } else if (rc != SFTP_ABORT) {
            SHELL_DD_LOG("raw DL failed (rc=%d), switching to base64", rc);
            rawFailed = true;
            rewindLocal();
        } else {
            return rc;
        }
    }

    ShowStatusId(IDS_LOG_SHELL_BASE64, nullptr, true);
    const int b64Rc = ShellDdDownloadBase64(cs, remotePath, remoteNameW,
                                            localfile, localNameW, hintedSize, startedAt, outSizeLoaded, textMode);
    if (rawFailed && b64Rc == SFTP_OK)
        cs->shell_dd_b64only = true;
    return b64Rc;
}

int ShellDdUploadFile(
    pConnectSettings cs,
    const std::string& remotePath,
    LPCWSTR remoteNameW,
    HANDLE localfile,
    LPCWSTR localNameW,
    int64_t fileSize,
    int64_t resumeFrom,
    int64_t* outSizeLoaded,
    bool textMode)
{
    if (!cs || !cs->session || !IsValidFileHandle(localfile) || !outSizeLoaded)
        return SFTP_FAILED;
    if (!ShellCommandIsSafe(ShellNormalizeScpPath(remotePath)))
        return SFTP_WRITEFAILED;

    // Forced mode uses the persistent interactive shell channel only.
    if (cs->shell_transfer_force) {
        cs->shell_dd_b64only = true;
        SHELL_DD_LOG("UL forced mode: using persistent shell base64 path");
    } else if (cs->scpShellChannel) {
        // Legacy non-forced mode may use exec channels for raw transfer.
        // Release persistent shell first on hosts with single-channel limits.
        SHELL_DD_LOG("UL closing persistent scpShellChannel before fallback transfer");
        CloseScpShell(cs);
    }

    ShowStatusId(IDS_LOG_SHELL_UL_START, nullptr, true);

    // For resume: query the actual remote byte count so we skip the right amount.
    if (resumeFrom > 0) {
        textMode = false;
        int64_t remoteSize = ShellGetRemoteFileSize(cs, remotePath);
        if (remoteSize >= 0 && remoteSize <= fileSize)
            resumeFrom = remoteSize;
        else
            return SFTP_WRITEFAILED;
    }

    int64_t expectedRemoteSize = fileSize;
    if (textMode && resumeFrom == 0) {
        LARGE_INTEGER pos0{};
        if (SetFilePointerEx(localfile, pos0, nullptr, FILE_BEGIN)) {
            bool pendingCr = false;
            int64_t convertedTotal = 0;
            bool binary = false;
            std::array<char, SFTP_SCP_BLOCK_SIZE> preBuf{};
            DWORD rd = 0;
            while (ReadFile(localfile, preBuf.data(), static_cast<DWORD>(preBuf.size()), &rd, nullptr) && rd > 0) {
                for (DWORD i = 0; i < rd; ++i) {
                    if (preBuf[i] == 0) {
                        binary = true;
                        break;
                    }
                }
                if (binary) break;
                CountCrLfToLf(preBuf.data(), rd, pendingCr, convertedTotal);
            }
            if (binary) {
                textMode = false;
            } else {
                if (pendingCr) ++convertedTotal;
                expectedRemoteSize = convertedTotal;
            }
        }
        SetFilePointerEx(localfile, pos0, nullptr, FILE_BEGIN);
    }

    bool rawFailed = false;
    if (!cs->shell_dd_b64only) {
        int rc = ShellDdUploadRaw(cs, remotePath, remoteNameW,
                                  localfile, localNameW, fileSize, resumeFrom, outSizeLoaded, textMode);
        if (rc == SFTP_OK) {
            // Verify remote size when wc -c is available; unknown (-1) keeps success.
            int64_t remoteSize = ShellGetRemoteFileSize(cs, remotePath);
            if (remoteSize < 0 || remoteSize == expectedRemoteSize) {
                return SFTP_OK;
            }
            SHELL_DD_LOG("raw UL size mismatch: remote=%lld expected=%lld, switching to base64",
                         (long long)remoteSize, (long long)expectedRemoteSize);
            rawFailed = true;
            LARGE_INTEGER pos0{};
            SetFilePointerEx(localfile, pos0, nullptr, FILE_BEGIN);
            *outSizeLoaded = 0;
            resumeFrom = 0;
        } else if (rc != SFTP_ABORT) {
            SHELL_DD_LOG("raw UL failed (rc=%d), switching to base64", rc);
            rawFailed = true;
            LARGE_INTEGER pos0{};
            SetFilePointerEx(localfile, pos0, nullptr, FILE_BEGIN);
            *outSizeLoaded = 0;
            resumeFrom = 0;
        } else {
            return rc;
        }
    }

    ShowStatusId(IDS_LOG_SHELL_BASE64, nullptr, true);
    const int b64Rc = ShellDdUploadBase64(cs, remotePath, remoteNameW,
                                          localfile, localNameW, fileSize, expectedRemoteSize,
                                          resumeFrom, outSizeLoaded, textMode);
    if (rawFailed && b64Rc == SFTP_OK)
        cs->shell_dd_b64only = true;
    return b64Rc;
}

static std::string BaseNameFromPath(const std::string& path)
{
    if (path.empty())
        return "upload.bin";
    std::string normalized = path;
    if (normalized.size() >= 2 && normalized.front() == '"' && normalized.back() == '"')
        normalized = normalized.substr(1, normalized.size() - 2);
    size_t pos = normalized.find_last_of('/');
    if (pos == std::string::npos || pos + 1 >= normalized.size())
        return normalized;
    return normalized.substr(pos + 1);
}

int ShellScpUploadFile(
    pConnectSettings cs,
    const std::string& remotePathArg,
    LPCWSTR remoteNameW,
    HANDLE localfile,
    LPCWSTR localNameW,
    int64_t fileSize,
    bool textMode,
    int64_t* outSizeLoaded,
    long mtime)
{
    if (!cs || !cs->session || !IsValidFileHandle(localfile) || !outSizeLoaded)
        return SFTP_FAILED;
    if (!ShellCommandIsSafe(remotePathArg))
        return SFTP_WRITEFAILED;

    *outSizeLoaded = 0;

    auto channel = ConnectChannel(cs->session.get(), cs->sock);
    if (!channel)
        return SFTP_FAILED;

    // scp -t runs through the remote login shell: without quoting, shell
    // metacharacters coming from a remote directory listing would be
    // interpreted (command injection).  Single-quote the whole argument;
    // ShellQuoteSingle escapes embedded single quotes as '\''.
    std::string cmd = (mtime > 0) ? "scp -pt '" : "scp -t '";
    cmd += string_util::ShellQuoteSingle(remotePathArg);
    cmd += "'";
    if (!SendChannelCommandNoEof(cs->session.get(), channel.get(), cmd.c_str(), cs->sock)) {
        DisconnectShell(channel.get());
        return SFTP_WRITEFAILED;
    }

    std::string ackErr;
    if (!ScpReadAck(channel.get(), cs, ackErr)) {
        if (!ackErr.empty())
            ShowStatus(ackErr.c_str());
        DisconnectShell(channel.get());
        return SFTP_WRITEFAILED;
    }

    const std::string baseName = BaseNameFromPath(remotePathArg);
    std::array<char, 1024> header{};

    // The SCP sink protocol reads EXACTLY the byte count declared in the
    // header. In text mode the wire size differs from the file size, so
    // compute it precisely with a streaming pre-pass using the same
    // conversion rules as the send loop (including chunk-boundary CRLF).
    // A lone CR at end of file is sent as one extra byte by the send loop,
    // so it must be part of the declared size as well.
    int64_t declaredSize = fileSize;
    bool pendingCr = false;
    if (textMode) {
        LARGE_INTEGER pos0{};
        pos0.QuadPart = 0;
        SetFilePointerEx(localfile, pos0, nullptr, FILE_BEGIN);
        int64_t convertedTotal = 0;
        std::vector<char> preBuf(SFTP_SCP_BLOCK_SIZE * 2);
        DWORD rd = 0;
        while (ReadFile(localfile, preBuf.data(), (DWORD)preBuf.size(), &rd, nullptr) && rd > 0)
            CountCrLfToLf(preBuf.data(), rd, pendingCr, convertedTotal);
        if (pendingCr)
            ++convertedTotal;         // trailing lone CR is written after the loop
        SetFilePointerEx(localfile, pos0, nullptr, FILE_BEGIN);
        pendingCr = false;
        declaredSize = convertedTotal;
    }

    if (mtime > 0) {
        char tHdr[64]{};
        _snprintf_s(tHdr, sizeof(tHdr), _TRUNCATE, "T%ld 0 %ld 0\n", mtime, mtime);
        if (!ScpWriteAll(channel.get(), cs, tHdr, strlen(tHdr), SFTP_SCP_WRITE_IDLE_TIMEOUT_MS) ||
            !ScpReadAck(channel.get(), cs, ackErr)) {
            if (!ackErr.empty())
                ShowStatus(ackErr.c_str());
            DisconnectShell(channel.get());
            return SFTP_WRITEFAILED;
        }
    }

    _snprintf_s(header.data(), header.size(), _TRUNCATE, "C%04o %lld %s\n", cs->filemod & 0777, (long long)declaredSize, baseName.c_str());
    if (!ScpWriteAll(channel.get(), cs, header.data(), strlen(header.data()), SFTP_SCP_WRITE_IDLE_TIMEOUT_MS) ||
        !ScpReadAck(channel.get(), cs, ackErr)) {
        if (!ackErr.empty())
            ShowStatus(ackErr.c_str());
        DisconnectShell(channel.get());
        return SFTP_WRITEFAILED;
    }

    std::vector<char> dataBuf(textMode ? (SFTP_SCP_BLOCK_SIZE * 2) : (SFTP_MAX_WRITE_SIZE * 8));
    std::vector<char> encBuf(textMode ? (SFTP_SCP_BLOCK_SIZE * 2 + 16) : 0);
    const SYSTICKS starttime = get_sys_ticks();
    DWORD len = 0;
    while (ReadFile(localfile, dataBuf.data(), (DWORD)dataBuf.size(), &len, nullptr) && len > 0) {
        size_t sendLen = len;
        if (textMode)
            sendLen = CrLfToLfStateful(dataBuf.data(), len, encBuf.data(), pendingCr);
        const char* sendBuf = textMode ? encBuf.data() : dataBuf.data();
        if (!ScpWriteAll(channel.get(), cs, sendBuf, sendLen, SFTP_SCP_WRITE_IDLE_TIMEOUT_MS)) {
            DisconnectShell(channel.get());
            return SFTP_WRITEFAILED;
        }
        *outSizeLoaded += len;
        if (UpdatePercentBar(cs, GetPercent(*outSizeLoaded, fileSize), localNameW, remoteNameW)) {
            DisconnectShell(channel.get());
            return SFTP_ABORT;
        }
    }
    if (textMode && pendingCr) {
        // A trailing lone CR at end of file.
        const char cr = '\r';
        if (!ScpWriteAll(channel.get(), cs, &cr, 1, SFTP_SCP_WRITE_IDLE_TIMEOUT_MS)) {
            DisconnectShell(channel.get());
            return SFTP_WRITEFAILED;
        }
    }

    LARGE_INTEGER measured{};
    if (!GetFileSizeEx(localfile, &measured) || *outSizeLoaded != measured.QuadPart) {
        DisconnectShell(channel.get());
        return SFTP_READFAILED;
    }
    const char zero = 0;
    if (!ScpWriteAll(channel.get(), cs, &zero, 1, SFTP_SCP_WRITE_IDLE_TIMEOUT_MS) ||
        !ScpReadAck(channel.get(), cs, ackErr)) {
        if (!ackErr.empty())
            ShowStatus(ackErr.c_str());
        DisconnectShell(channel.get());
        return SFTP_WRITEFAILED;
    }

    DisconnectShell(channel.get());
    ShowTransferSpeedIfLarge("Upload speed", *outSizeLoaded, starttime);
    return SFTP_OK;
}
