#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <memory>
#include "SftpClient.h"

bool ContainsNonAscii(LPCWSTR text) noexcept;
bool PrepareScpTransferSession(pConnectSettings cs);
std::string BuildScpPathArgument(const std::string& path);
bool OpenScpDownloadChannel(
    pConnectSettings ConnectSettings,
    const char* filename,
    std::unique_ptr<ISshChannel>& outChannel,
    libssh2_struct_stat* outInfo);

bool ShellRunPersistentCommand(
    pConnectSettings cs,
    const std::string& command,
    std::vector<std::string>& outLines,
    int* outExitCode = nullptr);

bool ShellSetRemoteMtime(pConnectSettings cs, const std::string& remotePath, long mtime);

int ShellDdDownloadFile(
    pConnectSettings cs,
    const std::string& remotePathArg,
    LPCWSTR remoteNameW,
    HANDLE localfile,
    LPCWSTR localNameW,
    int64_t fileSize,
    int64_t resumeFrom,
    int64_t* outSizeLoaded,
    bool textMode = false);

int ShellDdUploadFile(
    pConnectSettings cs,
    const std::string& remotePathArg,
    LPCWSTR remoteNameW,
    HANDLE localfile,
    LPCWSTR localNameW,
    int64_t fileSize,
    int64_t resumeFrom,
    int64_t* outSizeLoaded,
    bool textMode = false);

int ShellScpDownloadFile(
    pConnectSettings cs,
    const std::string& remotePathArg,
    LPCWSTR remoteNameW,
    HANDLE localfile,
    LPCWSTR localNameW,
    bool textMode,
    int64_t hintedFileSize,
    int64_t* outSizeLoaded);

int ShellScpUploadFile(
    pConnectSettings cs,
    const std::string& remotePathArg,
    LPCWSTR remoteNameW,
    HANDLE localfile,
    LPCWSTR localNameW,
    int64_t fileSize,
    bool textMode,
    int64_t* outSizeLoaded,
    long mtime = 0);
