#include "ProcessScanner.h"
#include <iostream>
#include <TlHelp32.h>

#define CHECK_INTERVAL_MS           2500

const wchar_t* AttackingProcesses[] = { L"Attacker.exe" };

ProcessScanner::ProcessScanner()
	: AttackDetector(CHECK_INTERVAL_MS)
{
}

void ProcessScanner::printStartMessage()
{
	std::cout << "ProcessScanner is on the case, watching for attackers\r\n";
}

void ProcessScanner::printStopMessage()
{
	std::cout << "ProcessScanner is shutting down, you're on your own against the bad guys\r\n";
}

void ProcessScanner::threadedWork()
{
	HANDLE hProcessSnapshot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	
	// get a snapshot of running processes
	hProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnapshot == INVALID_HANDLE_VALUE)
	{
		std::cout << "Couldn't create process snapshot, try again after wait_interval\r\n";
		return;
	}

	// iterate over the found processes, looking for matches against our list of suspects
	if (!Process32First(hProcessSnapshot, &pe32))
	{
		std::cout << "Couldn't get first process, try again\r\n";
		CloseHandle(hProcessSnapshot);
		return;
	}
	
	do
	{
		for (const wchar_t* susProcess : AttackingProcesses)
		{
			if (_wcsicmp(susProcess, pe32.szExeFile) == 0)
			{
				// we found an attacker running, exit
				attackDetected(0xBEEF);
			}
		}
	} while (Process32Next(hProcessSnapshot, &pe32));

	CloseHandle(hProcessSnapshot);
}