#include "aes_gcm.h"
#include <ntstatus.h>

AESGCM::~AESGCM()
{
    Cleanup();
}

// Freebie: initialize AES class
AESGCM::AESGCM(BYTE key[AES_256_KEY_SIZE])
{
    hAlg = 0;
    hKey = NULL;

    // create a handle to an AES-GCM provider
    nStatus = ::BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_AES_ALGORITHM,
        NULL,
        0);
    if (!NT_SUCCESS(nStatus))
    {
        wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", nStatus);
        Cleanup();
        return;
    }
    if (!hAlg)
    {
        wprintf(L"Invalid handle!\n");
    }
    nStatus = ::BCryptSetProperty(
        hAlg,
        BCRYPT_CHAINING_MODE,
        (BYTE *)BCRYPT_CHAIN_MODE_GCM,
        sizeof(BCRYPT_CHAIN_MODE_GCM),
        0);
    if (!NT_SUCCESS(nStatus))
    {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty ><\n", nStatus);
        Cleanup();
        return;
    }
    //        bcryptResult = BCryptGenerateSymmetricKey(algHandle, &keyHandle, 0, 0, (PUCHAR)&key[0], key.size(), 0);

    nStatus = ::BCryptGenerateSymmetricKey(
        hAlg,
        &hKey,
        NULL,
        0,
        key,
        AES_256_KEY_SIZE,
        0);
    if (!NT_SUCCESS(nStatus))
    {
        wprintf(L"**** Error 0x%x returned by BCryptGenerateSymmetricKey\n", nStatus);
        Cleanup();
        return;
    }
    DWORD cbResult = 0;
    nStatus = ::BCryptGetProperty(
        hAlg,
        BCRYPT_AUTH_TAG_LENGTH,
        (BYTE *)&authTagLengths,
        sizeof(authTagLengths),
        &cbResult,
        0);
    if (!NT_SUCCESS(nStatus))
    {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty when calculating auth tag len\n", nStatus);
    }
}

void AESGCM::Decrypt(BYTE *nonce, size_t nonceLen, BYTE *data, size_t dataLen, BYTE *macTag, size_t macTagLen)
{
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO paddingInfo;
    ptBufferSize = 0;
    NTSTATUS ret;
    BCRYPT_INIT_AUTH_MODE_INFO(paddingInfo);
    paddingInfo.pbTag = macTag;
    paddingInfo.cbTag = macTagLen;
    paddingInfo.pbNonce = nonce;
    paddingInfo.cbNonce = nonceLen;
    if ((ret = BCryptDecrypt(hKey, data, dataLen, &paddingInfo, nonce, nonceLen, NULL, ptBufferSize, &ptBufferSize, 0)) != STATUS_SUCCESS)
    {
        wprintf(L"BCryptDecrypt failed with error code: %x\n", ret);
        return;
    }
    if (plaintext != NULL)
    {
        delete[] plaintext;
    }
    plaintext = new BYTE[ptBufferSize];
    if ((ret = BCryptDecrypt(hKey, data, dataLen, &paddingInfo, nonce, nonceLen, plaintext, ptBufferSize, &ptBufferSize, 0)) != STATUS_SUCCESS)
    {
        wprintf(L"BCryptDecrypt failed with error code: %x\n", ret);
    }
}

void AESGCM::Encrypt(BYTE *nonce, size_t nonceLen, BYTE *data, size_t dataLen)
{
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO paddingInfo;
    ULONG ciphertextLen = 0;
    NTSTATUS ret;
    BCRYPT_INIT_AUTH_MODE_INFO(paddingInfo);
    if (tag)
    {
        delete[] tag;
    }
    if (ciphertext)
    {
        delete[] ciphertext;
    }
    tag = new BYTE[authTagLengths.dwMinLength];
    paddingInfo.pbTag = tag;
    paddingInfo.cbTag = authTagLengths.dwMinLength;
    paddingInfo.pbNonce = nonce;
    paddingInfo.cbNonce = nonceLen;

    if ((ret = BCryptEncrypt(hKey, data, dataLen, &paddingInfo, nonce, nonceLen, ciphertext, ciphertextLen, &ciphertextLen, 0)) != STATUS_SUCCESS)
    {
        wprintf(L"BCryptEncrypt failed with error code: %x\n", ret);
    }
    ciphertext = new BYTE[ciphertextLen];
    if ((ret = BCryptEncrypt(hKey, data, dataLen, &paddingInfo, nonce, nonceLen, ciphertext, ciphertextLen, &ciphertextLen, 0)) != STATUS_SUCCESS)
    {
        wprintf(L"BCryptEncrypt failed with error code: %x\n", ret);
    }
}

void AESGCM::Cleanup()
{
    if (hAlg)
    {
        ::BCryptCloseAlgorithmProvider(hAlg, 0);
        hAlg = NULL;
    }
    if (hKey)
    {
        ::BCryptDestroyKey(hKey);
        hKey = NULL;
    }
    if (tag)
    {
        delete[] tag;
    }
    if (ciphertext)
    {
        delete[] ciphertext;
    }
    if (plaintext)
    {
        delete[] plaintext;
    }
}
