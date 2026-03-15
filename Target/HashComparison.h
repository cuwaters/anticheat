#pragma once

#include <Windows.h>

class HashComparer
{
public:
    void Start();
    void Stop();
private:
    static unsigned __stdcall StaticThreadStart(void* args);

    int readContentFile(const char* filename, BYTE** ppBytes, DWORD* pFileSize);
    void bytesToHexString(BYTE* bytes, DWORD dwSize, char* hashString);
    DWORD hashDataBuffer(BYTE** ppHashResult, BYTE* dataToHash, DWORD dataSize);
    DWORD getTargetDirectory(char* buffer, DWORD bufferSize);
    void compareHashes();

    HANDLE m_hThread = INVALID_HANDLE_VALUE;
    HANDLE m_hStopEvent = INVALID_HANDLE_VALUE;
    unsigned int m_ThreadId = 0;
};