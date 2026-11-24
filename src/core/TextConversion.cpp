#include <windows.h>
#include <algorithm>
#include <string>
#include <vector>
#include <cstring>
#include <cstdint>
#include <climits>
#include "ScpTransferInternal.h"

int ConvertCrToCrLf(LPSTR data, size_t len, size_t capacity, bool* pLastWasCr)
{
    if (!data || !pLastWasCr || len > capacity)
        return 0;

    bool lastWasCr = *pLastWasCr;
    std::string result;
    result.reserve(len + len / 2); // worst case expansion

    for (size_t i = 0; i < len; ++i) {
        const unsigned char c = static_cast<unsigned char>(data[i]);
        if (c == '\r') {
            lastWasCr = true;
            result.push_back('\r');
        } else if (c == '\n') {
            if (!lastWasCr)
                result.push_back('\r');
            result.push_back('\n');
            lastWasCr = false;
        } else {
            lastWasCr = false;
            result.push_back(c);
        }
    }

    if (result.size() > capacity || result.size() > INT_MAX)
        return -1;
    *pLastWasCr = lastWasCr;
    memcpy(data, result.data(), result.size());
    return static_cast<int>(result.size());
}

int ConvertCrLfToLf(LPSTR data, size_t len)
{
    if (!data || len == 0)
        return 0;

    size_t out = 0;
    for (size_t i = 0; i < len; ++i) {
        const char ch = data[i];
        if (ch == '\r' && i + 1 < len && data[i + 1] == '\n') {
            continue;
        }
        data[out++] = ch;
    }
    return static_cast<int>(out);
}

// Counts the CRLF->LF output size of a chunk, carrying a pending lone CR
// from the previous chunk (see CrLfToLfStateful). total accumulates the kept
// byte count; a still-pending CR at the end is NOT included here, so callers
// must add 1 if pendingCr is true after the final chunk.
void CountCrLfToLf(const char* data, size_t len, bool& pendingCr, int64_t& total)
{
    size_t kept = 0;
    size_t i = 0;
    if (pendingCr) {
        pendingCr = false;
        ++kept;                       // lone CR from previous chunk…
        if (len > 0 && data[0] == '\n') { i = 1; }  // …unless it pairs here
    }
    for (; i < len; ++i) {
        if (data[i] == '\r' && i + 1 < len && data[i + 1] == '\n')
            continue;                 // drop CR of an in-buffer CRLF
        if (data[i] == '\r' && i + 1 == len) {
            pendingCr = true;         // may pair with the next chunk
            continue;
        }
        ++kept;
    }
    total += static_cast<int64_t>(kept);
}

// Converts one chunk with cross-chunk CRLF state. Separate in/out buffers,
// so no in-place aliasing hazards; outCap must be >= len + 1 (worst case:
// carried lone CR followed by a chunk with nothing dropped).
size_t CrLfToLfStateful(const char* in, size_t len, char* out, bool& pendingCr)
{
    size_t o = 0;
    size_t i = 0;
    if (pendingCr) {
        pendingCr = false;
        if (len > 0 && in[0] == '\n') {
            out[o++] = '\n';           // complete the split CRLF: keep the LF
            i = 1;
        } else {
            out[o++] = '\r';           // previous chunk ended with a lone CR
        }
    }
    for (; i < len; ++i) {
        const char ch = in[i];
        if (ch == '\r') {
            if (i + 1 < len) {
                if (in[i + 1] == '\n') continue;   // drop CR of an in-buffer CRLF
            } else {
                pendingCr = true;                  // may pair with the next chunk
                continue;
            }
        }
        out[o++] = ch;
    }
    return o;
}

void DownloadTextFilter::AppendConverted(const char* data, size_t len, std::vector<char>& out)
{
    out.reserve(out.size() + len + len / 8 + 1);
    for (size_t i = 0; i < len; ++i) {
        const unsigned char c = static_cast<unsigned char>(data[i]);
        if (c == '\r') {
            lastWasCr_ = true;
            out.push_back('\r');
        } else if (c == '\n') {
            if (!lastWasCr_)
                out.push_back('\r');
            out.push_back('\n');
            lastWasCr_ = false;
        } else {
            lastWasCr_ = false;
            out.push_back(static_cast<char>(c));
        }
    }
}

size_t DownloadTextFilter::Release(std::vector<char>& out)
{
    deciding_ = false;
    const size_t before = out.size();
    if (text_) {
        AppendConverted(held_.data(), held_.size(), out);
    } else {
        out.insert(out.end(), held_.begin(), held_.end());
    }
    held_.clear();
    held_.shrink_to_fit();
    return out.size() - before;
}

size_t DownloadTextFilter::Feed(const char* data, size_t len, std::vector<char>& out)
{
    if (!data || len == 0)
        return 0;
    if (deciding_) {
        held_.insert(held_.end(), data, data + len);
        const auto windowEnd = held_.begin() + static_cast<std::ptrdiff_t>((std::min)(held_.size(), kWindow));
        if (std::find(held_.begin(), windowEnd, '\0') != windowEnd)
            text_ = false;
        if (!text_ || held_.size() >= kWindow)
            return Release(out);
        return 0;
    }
    const size_t before = out.size();
    if (text_)
        AppendConverted(data, len, out);
    else
        out.insert(out.end(), data, data + len);
    return out.size() - before;
}

size_t DownloadTextFilter::Finish(std::vector<char>& out)
{
    return deciding_ ? Release(out) : 0;
}
