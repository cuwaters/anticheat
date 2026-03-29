#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>

bool getTargetHandle(HANDLE* pHandle, DWORD* pPid)
{
	HANDLE hProcessSnapshot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	// get a snapshot of running processes
	hProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnapshot != INVALID_HANDLE_VALUE)
	{
		// iterate over the found processes, looking for matches against our list of suspects
		if (Process32First(hProcessSnapshot, &pe32))
		{
			do
			{
				if (_wcsicmp(L"target.exe", pe32.szExeFile) == 0)
				{
					*pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
					*pPid = pe32.th32ProcessID;
					break;
				}
			} while (Process32Next(hProcessSnapshot, &pe32));
		}
	}

	CloseHandle(hProcessSnapshot);
	return *pHandle != INVALID_HANDLE_VALUE;
}

bool getPrimaryModuleBaseAddress(DWORD pid, void** ppBaseAddress, DWORD* pSize)
{
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;
	bool found = false;

	// Take a snapshot of all modules in the specified process.
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	if (hModuleSnap == INVALID_HANDLE_VALUE)
	{
		return(false);
	}

	// Set the size of the structure before using it.
	me32.dwSize = sizeof(MODULEENTRY32);

	// Retrieve information about the first module,
	// and exit if unsuccessful
	if (!Module32First(hModuleSnap, &me32))
	{
		CloseHandle(hModuleSnap);           // clean the snapshot object
		return(false);
	}

	// Now walk the module list of the process,
	// and display information about each module
	do
	{
		if (_wcsicmp(L"target.exe", me32.szModule) == 0) // look for the module whose name matches the process exe
		{
			*ppBaseAddress = me32.modBaseAddr;
			*pSize = me32.modBaseSize;
			found = true;
		}
	} while (!found && Module32Next(hModuleSnap, &me32));

	CloseHandle(hModuleSnap);
	return found;
}

bool findKeyString(void* buffer, DWORD bufferSize, DWORD* pOffset)
{
	const char* keyString = "This is a string in .text section";
	for (DWORD i = 0; i < bufferSize; ++i)
	{
		char* current = (char*)buffer + i;
		if (strcmp(current, keyString) == 0)
		{
			*pOffset = i;
			return true;
		}
	}

	return false;
}

int main()
{
	constexpr DWORD durationMS = 10 * 1000;
	constexpr DWORD sleepTimeMS = 500;

	std::cout << "Attacker is running for " << durationMS / 1000 << " seconds\r\n";
	DWORD start = GetTickCount();

	while (GetTickCount() - start < durationMS)
	{
		HANDLE hProc = INVALID_HANDLE_VALUE;
		DWORD pid = 0;
		BYTE* pBaseAddress = nullptr;
		DWORD processSize = 0;
		if (false && getTargetHandle(&hProc, &pid)) // the target isn't able to detect this with enough accuracy, so disable memory modification for now
		{
			if (getPrimaryModuleBaseAddress(pid, (void**)&pBaseAddress, &processSize))
			{
				void* buffer = malloc(processSize);
				memset(buffer, 0, processSize); // zero-fill the buffer, so we don't get false positives
				size_t bytesRead = 0;
				if (ReadProcessMemory(hProc, pBaseAddress, buffer, processSize, &bytesRead))
				{
					std::cout << "We read the memory \r\n";
					// Process memory was read into our buffer, now we can read or change it
					DWORD keyOffset = -1;
					if (findKeyString(buffer, processSize, &keyOffset))
					{
						const char* dataToWrite = "This is b string in .text section";
						size_t bytesWritten = 0;
						BOOL result = WriteProcessMemory(hProc, (void*)(pBaseAddress + keyOffset), dataToWrite, sizeof(dataToWrite), &bytesWritten);
						if (result == TRUE)
						{
							std::cout << "Wrote " << bytesWritten << " bytes to address " << std::hex << std::uppercase << (void*)(pBaseAddress + keyOffset) << std::endl;
						}
						else
						{
							std::cout << "Writing failed with error: " << GetLastError() << std::endl;
						}
					}
				}

				if (buffer != nullptr)
				{
					free(buffer);
					buffer = nullptr;
				}
				if (hProc != INVALID_HANDLE_VALUE)
				{
					CloseHandle(hProc);
					hProc = INVALID_HANDLE_VALUE;
				}
			}
		}
		Sleep(sleepTimeMS);
	}

	std::cout << "Attacker is exiting";
}