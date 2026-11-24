#pragma once
#include <string>
#include "SftpClient.h"

std::string ReadIniString(LPCSTR section, LPCSTR key, LPCSTR defaultVal, LPCSTR iniFileName);
std::string JumpPasswordStoreName(const std::string& displayName);
bool LoadProxySettingsFromNr(int proxynr, pConnectSettings ConnectResults, LPCSTR iniFileName);
bool LoadServerSettings(LPCSTR DisplayName, pConnectSettings ConnectResults, LPCSTR iniFileName);
