#pragma once

#include <Windows.h>
#include "AttackDetector.h"

class HashComparer : public AttackDetector
{
public:
    HashComparer();
private:
    void threadedWork() override;
    int readContentFile(const char* filename, BYTE** ppBytes, DWORD* pFileSize);
    void bytesToHexString(BYTE* bytes, DWORD dwSize, char* hashString);
    DWORD hashDataBuffer(BYTE** ppHashResult, BYTE* dataToHash, DWORD dataSize);
    DWORD getTargetDirectory(char* buffer, DWORD bufferSize);
    void compareHashes();

};