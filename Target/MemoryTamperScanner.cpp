#include "MemoryTamperScanner.h"
#include <cstdint>
#include <iostream>

#define CHECK_INTERVAL_MS           1000

MemoryTamperScanner::MemoryTamperScanner()
	: AttackDetector(CHECK_INTERVAL_MS)
{
	IMAGE_SECTION_HEADER textSection = {};
	bool found = findTextSection(&textSection);

	// we somehow don't have a text section, so aren't running code, including this code?
	if (!found)
	{
		exit(1);
	}

	m_params.base_address = (uintptr_t)((uintptr_t)GetModuleHandle(nullptr) + textSection.VirtualAddress);
	m_params.size = textSection.Misc.VirtualSize;
	m_params.process = GetCurrentProcess();
}

bool MemoryTamperScanner::findTextSection(IMAGE_SECTION_HEADER* pSectionHeader)
{
	constexpr uint16_t dosMagicValue = ('M' | 'Z' << 8);
	constexpr uint32_t peMagicValue = ('P' | 'E' << 8);

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)GetModuleHandle(nullptr);
	if (dosHeader != nullptr)
	{
		if (dosHeader->e_magic == dosMagicValue)
		{
			PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)dosHeader + dosHeader->e_lfanew);
			if (ntHeaders != nullptr)
			{
				if (ntHeaders->Signature == peMagicValue)
				{
					uint32_t numSections = ntHeaders->FileHeader.NumberOfSections;
					PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)((uintptr_t)ntHeaders + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER) + ntHeaders->FileHeader.SizeOfOptionalHeader);

					for (int i = 0; i < numSections; ++i)
					{
						IMAGE_SECTION_HEADER section = sections[i];
						if (strcmp((const char*)section.Name, ".text") == 0)
						{
							*pSectionHeader = section;
							return true;
						}
					}
				}
			}
		}
	}

	return false;
}

void MemoryTamperScanner::threadedWork()
{
}

void MemoryTamperScanner::printStartMessage()
{
	std::cout << "MemoryTamperScanner is watching for attackers\r\n";
}

void MemoryTamperScanner::printStopMessage()
{
	std::cout << "MemoryTamperScanner shutting down \r\n";
}
