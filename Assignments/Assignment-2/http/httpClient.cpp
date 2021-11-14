#include <windows.h>
#include <string>
#include <iostream>
#include <winhttp.h>

std::wstring makeHttpRequest(std::wstring fqdn, int port, std::wstring uri, bool useTLS)
{
    std::wstring result = L"";
    HINTERNET hSession = NULL,
              hConnect = NULL,
              hRequest = NULL;
    BOOL bResult = FALSE;
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer;

    hSession = WinHttpOpen(NULL, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (hSession)
    {
        hConnect = WinHttpConnect(hSession, fqdn.data(), port, 0);
    }
    if (hConnect)
    {
        hRequest = WinHttpOpenRequest(hConnect, L"GET", uri.data(),
                                      NULL, WINHTTP_NO_REFERER,
                                      WINHTTP_DEFAULT_ACCEPT_TYPES,
                                      useTLS? WINHTTP_FLAG_SECURE : 0);
    }
    if (!hRequest)
    {
        std::cerr << "Error: " << GetLastError() << std::endl;
    }
    else
    {
        bResult = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
        if (bResult)
        {
            bResult = WinHttpReceiveResponse(hRequest, NULL);
        }
        if (bResult)
        {
            do
            {
                if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
                {
                    std::cerr << "Error: " << GetLastError() << std::endl;
                    break;
                }
                pszOutBuffer = new char[dwSize + 1];
                ZeroMemory(pszOutBuffer, dwSize+1);
                if (!WinHttpReadData(hRequest, pszOutBuffer, dwSize, &dwDownloaded))
                {
                    std::cerr << "Error: " << GetLastError() << std::endl;
                    break;
                }
                wchar_t * tempString = new wchar_t[dwSize + 1];
                std::mbstowcs(tempString, pszOutBuffer, dwSize+1);
                result.append(tempString);
                delete [] pszOutBuffer;
                delete [] tempString;
                if (!dwDownloaded)
                    break;
            } while (dwSize > 0);
        }
    }
    if (hRequest)
        WinHttpCloseHandle(hRequest);
    if (hConnect)
        WinHttpCloseHandle(hConnect);
    if (hSession)
        WinHttpCloseHandle(hSession);
    return result;
}

int wmain(int argc, wchar_t *argv[])
{
    if (argc != 5)
    {
        std::wcout << L"Incorrect number of arguments: you need 4 positional arguemts" << std::endl;
        return 0;
    }

    std::wstring fqdn = std::wstring(argv[1]);
    int port = std::stoi(argv[2]);
    std::wstring uri = std::wstring(argv[3]);
    int useTLS = std::stoi(argv[4]);
    bool tls;
    if (useTLS == 1)
    {
        tls = true;
    }
    else if (useTLS == 0)
    {
        tls = false;
    }
    else
    {
        std::wcout << L"bad value for useTls" << std::endl;
        return 0;
    }
    std::wcout << makeHttpRequest(fqdn, port, uri, tls) << std::endl;
    return 0;
}