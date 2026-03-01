// Target.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <stdio.h>
#include "HashComparison.h"

const char* secretString = "This is a string";

int main(int argc, char* argv[])
{
    printf("Hello World! \n");
    printf("%s\n", secretString);

    compareHashes();
}

// these functions will have significantly different implementations in kernel mode, so they are defined in this project specific user-mode file

DWORD getTargetDirectory(char* buffer, DWORD bufferSize)
{    
    DWORD pathLength = GetCurrentDirectoryA(bufferSize, buffer);
    buffer[pathLength++] = '\\';

    return pathLength;
}

int readContentFile(const char* filename, BYTE** ppBytes, DWORD* pFileSize)
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
