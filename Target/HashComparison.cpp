#include "HashComparison.h"

#include <bcrypt.h>
#include <process.h>

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)

#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

#define CHECK_INTERVAL_MS           2500

struct ExpectedFileHash
{
    const char* fileName;
    const char* expectedHashValue;
};

ExpectedFileHash files[] = { {"content1.dat", "3C1BD5AC79353515478E8EF446B2DB2895F31A09EBACA2D056DA9C2AD2E066A6"} };

HashComparer::HashComparer()
    : AttackDetector(CHECK_INTERVAL_MS)
{
}

void HashComparer::threadedWork()
{
    compareHashes();
}

// these functions will have significantly different implementations in kernel mode, so they are defined in this project specific user-mode file
DWORD HashComparer::getTargetDirectory(char* buffer, DWORD bufferSize)
{
    DWORD pathLength = GetCurrentDirectoryA(bufferSize, buffer);
    buffer[pathLength++] = '\\';

    return pathLength;
}

int HashComparer::readContentFile(const char* filename, BYTE** ppBytes, DWORD* pFileSize)
{
    HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (INVALID_HANDLE_VALUE == hFile)
    {
        return 1;
    }

    LARGE_INTEGER size;
    size.QuadPart = 0;
    if (!GetFileSizeEx(hFile, &size))
    {
        CloseHandle(hFile);
        return 2;
    }

    *pFileSize = size.LowPart;

    *ppBytes = (BYTE*)HeapAlloc(GetProcessHeap(), 0, *pFileSize);
    DWORD bytesRead = 0;
    if (!ReadFile(hFile, *ppBytes, *pFileSize, &bytesRead, NULL))
    {
        CloseHandle(hFile);
        return 3;
    }

    CloseHandle(hFile);

    return 0;
}

void HashComparer::compareHashes()
{
    char path[MAX_PATH] = { 0 };
    DWORD dirLength = getTargetDirectory(path, MAX_PATH);

    for (ExpectedFileHash& current : files)
    {
        // read the content file
        BYTE* pFileBytes = NULL;
        DWORD fileSize = 0;

        // append the current filename to the full path
        for (int i = 0; i < strlen(current.fileName); ++i)
        {
            path[dirLength + i] = current.fileName[i];
        }

        int res = readContentFile(path, &pFileBytes, &fileSize);

        // if we couldn't read the file, skip this file (that's likely an attack, though)
        if (res != 0)
        {
            continue;
        }

        BYTE* pHashBytes = NULL;
        DWORD hashSize = 0;
        hashSize = hashDataBuffer(&pHashBytes, pFileBytes, fileSize);

        // if hashing failed, skip this file and check the next
        if (hashSize == 0)
        {
            continue;
        }

        char hashString[65] = { 0 };
        bytesToHexString(pHashBytes, hashSize, hashString);
        int compare_result = strcmp(current.expectedHashValue, hashString);

        if (compare_result != 0)
        {
            // there was an attack, exit
            exit(111);
        }
    }
}

void HashComparer::bytesToHexString(BYTE* bytes, DWORD dwSize, char* hashString)
{
    const char hex_str[] = "0123456789ABCDEF";

    for (DWORD i = 0; i < dwSize; ++i)
    {
        hashString[i * 2 + 0] = hex_str[(bytes[i] >> 4) & 0x0f];
        hashString[i * 2 + 1] = hex_str[(bytes[i]) & 0x0f];
    }
}

/// <summary>
/// Hashes the data in dataToHash, and stores the resulting hash in the buffer pointed to by ppHashResult
/// </summary>
/// <param name="ppHashResult">pointer to a byte pointer that will be written with the output value.  Callers are responsible for freeing this buffer with HeapFree</param>
/// <param name="dataToHash">The input data to hash</param>
/// <param name="dataSize">the size of the input data</param>
/// <returns>The size of the buffer holding the output hash</returns>
DWORD HashComparer::hashDataBuffer(BYTE** ppHashResult, BYTE* dataToHash, DWORD dataSize)
{
    BCRYPT_ALG_HANDLE hAlg = 0;
    BCRYPT_HASH_HANDLE hHash = 0;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BYTE* pbHashObject = NULL;
    DWORD dwHashObject = 0;
    DWORD dwData = 0;
    DWORD dwHash = 0;

    // if we don't have a valid pointer to pointer for the output hash, return failure indicator
    if (NULL == ppHashResult)
    {
        return 0;
    }

    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_HASH_REUSABLE_FLAG)))
    {
        goto Cleanup;
    }

    if (!NT_SUCCESS(status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (BYTE*)&dwHashObject, sizeof(dwHashObject), &dwData, 0)))
    {
        goto Cleanup;
    }

    pbHashObject = (BYTE*)HeapAlloc(GetProcessHeap(), 0, dwHashObject);
    if (NULL == pbHashObject)
    {
        goto Cleanup;
    }

    if (!NT_SUCCESS(status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (BYTE*)&dwHash, sizeof(dwHash), &dwData, 0)))
    {
        goto Cleanup;
    }

    *ppHashResult = (BYTE*)HeapAlloc(GetProcessHeap(), 0, dwHash);
    if (NULL == *ppHashResult)
    {
        goto Cleanup;
    }

    if (!NT_SUCCESS(status = BCryptCreateHash(hAlg, &hHash, pbHashObject, dwHashObject, NULL, 0, BCRYPT_HASH_REUSABLE_FLAG)))
    {
        goto Cleanup;
    }

    // now we're ready to hash the data using BCryptHashData
    if (!NT_SUCCESS(status = BCryptHashData(hHash, dataToHash, dataSize, 0)))
    {
        goto Cleanup;
    }

    // BCryptFinishHash writes the hash value into pHashResult
    if (!NT_SUCCESS(status = BCryptFinishHash(hHash, *ppHashResult, dwHash, 0)))
    {
        dwHash = 0;
        goto Cleanup;
    }

Cleanup:
    if (hAlg)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        hAlg = 0;
    }

    if (hHash)
    {
        BCryptDestroyHash(hHash);
        hHash = 0;
    }

    if (pbHashObject)
    {
        HeapFree(GetProcessHeap(), 0, pbHashObject);
        pbHashObject = NULL;
    }

    return dwHash;
}