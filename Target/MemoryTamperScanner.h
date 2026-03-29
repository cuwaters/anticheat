#pragma once

#include "AttackDetector.h"

class MemoryTamperScanner : public AttackDetector
{
public:
	MemoryTamperScanner();

private:
    /* AttackDetector implementation */
    void threadedWork() override;
    void printStartMessage() override;
    void printStopMessage() override;

    bool findTextSection(IMAGE_SECTION_HEADER* sectionHeader);

	struct ThreadParams
	{
		uintptr_t base_address;
		size_t size;
		HANDLE process;
	};

	ThreadParams m_params;
};