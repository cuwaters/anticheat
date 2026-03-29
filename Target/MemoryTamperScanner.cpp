#include "MemoryTamperScanner.h"
#include <cstdint>
#include <iostream>
#include <Psapi.h>

#define CHECK_INTERVAL_MS           1000

MemoryTamperScanner::MemoryTamperScanner()
	: AttackDetector(CHECK_INTERVAL_MS)
{
	IMAGE_SECTION_HEADER textSection = {};
	bool found = findSectionByName(".text", &textSection);

	// we somehow don't have a text section, so aren't running code, including this code?
	if (!found)
	{
		exit(1);
	}

	m_params.base_address = (uintptr_t)((uintptr_t)GetModuleHandle(nullptr) + textSection.VirtualAddress);
	m_params.size = textSection.Misc.VirtualSize;
	m_params.process = GetCurrentProcess();
}

bool MemoryTamperScanner::findSectionByName(const char* name, IMAGE_SECTION_HEADER* pSectionHeader)
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
						if (strcmp((const char*)section.Name, name) == 0)
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
	uintptr_t pageRangeStart = m_params.base_address / 0x1000;
	uintptr_t pageRangeEnd = ((m_params.base_address + m_params.size) + 0xFFF) / 0x1000;

	PPSAPI_WORKING_SET_INFORMATION pwsi = nullptr;
	pwsi = (PPSAPI_WORKING_SET_INFORMATION)malloc(sizeof(PSAPI_WORKING_SET_INFORMATION));

	bool ret = QueryWorkingSet(m_params.process, (PVOID)pwsi, sizeof(PSAPI_WORKING_SET_INFORMATION));

	// do we need to allocate more space for pwsi?
	if (!ret && GetLastError() == ERROR_BAD_LENGTH)
	{
		// calculate needed size before we free the too-small object
		uint32_t objectSize = sizeof(PSAPI_WORKING_SET_BLOCK) * pwsi->NumberOfEntries + sizeof(pwsi->NumberOfEntries);
		free(pwsi);
		pwsi = (PPSAPI_WORKING_SET_INFORMATION)malloc(objectSize);
		if (pwsi == nullptr)
		{
			return;
		}
		QueryWorkingSet(m_params.process, (PVOID)pwsi, objectSize);
	}

	for (int i = 0; i < pwsi->NumberOfEntries; ++i)
	{
		PSAPI_WORKING_SET_BLOCK block = pwsi->WorkingSetInfo[i];
		if (pageRangeStart <= block.VirtualPage && block.VirtualPage <= pageRangeEnd)
		{
			if (FALSE == block.Shared)
			{
				// We're not using the shared version of this page, so someone else has locked it for writing
				printf("Tamper detected in memory range %p - %p (Page VirtualAddress: %p, ShareCount: %d)\n", (void*)m_params.base_address, (void*)(m_params.base_address + m_params.size), (void*)(block.VirtualPage * 0x1000), (int)block.ShareCount);
				attackDetected(0xB17E);
				break;
			}
		}
	}

	if (pwsi != nullptr)
	{
		free(pwsi);
		pwsi = nullptr;
	}
}

void MemoryTamperScanner::printStartMessage()
{
	std::cout << "MemoryTamperScanner is watching for attackers\r\n";
}

void MemoryTamperScanner::printStopMessage()
{
	std::cout << "MemoryTamperScanner shutting down \r\n";
}
