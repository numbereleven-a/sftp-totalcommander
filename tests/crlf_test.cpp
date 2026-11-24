// crlf_test.cpp — verifies CountCrLfToLf / CrLfToLfStateful agree with each
// other and with the naive whole-buffer ConvertCrLfToLf semantics, including
// CR/LF pairs split across chunk boundaries.
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include "ScpTransferInternal.h"

struct CrLfState { bool pendingCr = false; int64_t total = 0; };

void CountCrLfToLf(const char*, size_t, bool&, int64_t&);

size_t CrLfToLfStateful(const char*, size_t, char*, bool&);

// Reference: whole-buffer conversion (no chunking).
static std::string RefConvert(const std::string& in) {
    std::string out;
    for (size_t i = 0; i < in.size(); ++i) {
        if (in[i] == '\r' && i + 1 < in.size() && in[i + 1] == '\n') continue;
        out += in[i];
    }
    return out;
}

static int failures = 0;

static void RunCase(const std::string& content, size_t chunkSize) {
    // Counting pass
    CrLfState cs;
    for (size_t off = 0; off < content.size(); off += chunkSize)
        CountCrLfToLf(content.data() + off,
                      (std::min)(chunkSize, content.size() - off), cs.pendingCr, cs.total);
    if (cs.pendingCr) ++cs.total;   // trailing lone CR flushed at EOF

    // Conversion pass
    std::vector<char> inBuf(content.begin(), content.end());
    std::vector<char> outBuf(content.size() + 16);
    std::string converted;
    bool pendingCr = false;
    for (size_t off = 0; off < content.size(); off += chunkSize) {
        size_t n = (std::min)(chunkSize, content.size() - off);
        size_t outLen = CrLfToLfStateful(inBuf.data() + off, n, outBuf.data(), pendingCr);
        converted.append(outBuf.data(), outLen);
    }
    if (pendingCr) converted += '\r';

    const std::string ref = RefConvert(content);
    const bool okCount = (cs.total == (int64_t)ref.size());
    const bool okConv  = (converted == ref);
    if (!okCount || !okConv) {
        printf("FAIL chunk=%zu content=%s\n", chunkSize, content.c_str());
        printf("  counted=%lld ref=%zu\n", (long long)cs.total, ref.size());
        printf("  converted(%zu) vs ref(%zu)\n", converted.size(), ref.size());
        ++failures;
    }
}

int ConvertCrToCrLf(char*, size_t, size_t, bool*);
int main() {
    {
        std::vector<char> buffer(120001, '\n');
        buffer.back() = 'X';
        bool state = false;
        if (ConvertCrToCrLf(buffer.data(), 60000, 120000, &state) != 120000 || buffer.back() != 'X') ++failures;
        std::fill(buffer.begin(), buffer.end(), '\n');
        state = false;
        if (ConvertCrToCrLf(buffer.data(), 60000, 60000, &state) != -1 || buffer[60000] != '\n') ++failures;
    }
    const char* contents[] = {
        "a\r\nb\r\nc",
        "\r\nstart",
        "end\r\n",
        "lone\rcr\n",
        "split\r",
        "split\r\n",           // CRLF split across chunks when chunk=6? handled by cases below
        "\r\r\n\n\r\n",
        "plain ascii text only",
        "",
        "\r",
        "\r\n",
    };
    const size_t chunks[] = { 1, 2, 3, 4, 5, 7, 16, 1024 };
    for (const auto* c : contents)
        for (size_t ch : chunks)
            RunCase(c, ch);

    // Explicit split-CRLF case: "abc\r\nxyz" with chunk=4 → boundary between \r and \n
    {
        const std::string s = "abc\r\nxyz";
        CrLfState cs;
        CountCrLfToLf(s.data(), 4, cs.pendingCr, cs.total);   // "abc\r"
        CountCrLfToLf(s.data() + 4, s.size() - 4, cs.pendingCr, cs.total); // "\nxyz"
        if (cs.pendingCr) ++cs.total;
        if (cs.total != (int64_t)RefConvert(s).size()) { printf("FAIL explicit split count\n"); ++failures; }
    }

    // DownloadTextFilter: uniform 64 KiB NUL-byte detection and chunk-invariant LF->CRLF.
    {
        auto runFilter = [](const std::string& input, bool textMode, size_t chunk, bool& outIsText) {
            DownloadTextFilter filter(textMode);
            std::string out;
            std::vector<char> tmp;
            for (size_t off = 0; off < input.size(); off += chunk) {
                const size_t n = (std::min)(chunk, input.size() - off);
                tmp.clear();
                filter.Feed(input.data() + off, n, tmp);
                out.append(tmp.data(), tmp.size());
            }
            tmp.clear();
            filter.Finish(tmp);
            out.append(tmp.data(), tmp.size());
            outIsText = filter.IsText();
            return out;
        };

        // Small text file across all chunk sizes (including split \r + \n).
        const std::string smallText = "line1\nline2\r\nline3\rline4\n";
        const std::string smallExp  = "line1\r\nline2\r\nline3\rline4\r\n";
        for (size_t ch : {size_t{1}, size_t{2}, size_t{3}, size_t{7}, size_t{1024}}) {
            bool isText = false;
            const std::string got = runFilter(smallText, true, ch, isText);
            if (!isText || got != smallExp) {
                printf("FAIL DownloadTextFilter small text chunk=%zu\n", ch);
                ++failures;
            }
        }

        // NUL byte at 50 KiB (inside 64 KiB window) across 16 KiB chunks -> binary pass-through.
        std::string binInWindow(80 * 1024, 'A');
        binInWindow[10] = '\n';
        binInWindow[50 * 1024] = '\0';
        binInWindow[70 * 1024] = '\n';
        {
            bool isText = true;
            const std::string got = runFilter(binInWindow, true, 16 * 1024, isText);
            if (isText || got != binInWindow) {
                printf("FAIL DownloadTextFilter NUL inside 64 KiB window\n");
                ++failures;
            }
        }

        // NUL byte at 70 KiB (outside 64 KiB window) -> commits text mode at 64 KiB.
        std::string nulPastWindow(80 * 1024, 'B');
        nulPastWindow[10] = '\n';
        nulPastWindow[70 * 1024] = '\0';
        {
            bool isText = false;
            const std::string got = runFilter(nulPastWindow, true, 16 * 1024, isText);
            if (!isText || got.size() != nulPastWindow.size() + 1 || got[10] != '\r' || got[11] != '\n') {
                printf("FAIL DownloadTextFilter NUL outside 64 KiB window\n");
                ++failures;
            }
        }

        // Binary mode passes through unchanged.
        {
            bool isText = true;
            const std::string got = runFilter(smallText, false, 3, isText);
            if (isText || got != smallText) {
                printf("FAIL DownloadTextFilter binary mode\n");
                ++failures;
            }
        }
    }

    printf(failures ? "FAILED %d cases\n" : "ALL OK (%d failures)\n", failures);
    return failures ? 1 : 0;
}
