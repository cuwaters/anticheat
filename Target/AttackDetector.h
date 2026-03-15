#pragma once
#include <Windows.h>

class AttackDetector
{
public:
	virtual void Start();
	virtual void Stop();
protected:
	AttackDetector(int checkInterval);
	static unsigned __stdcall StaticThreadStart(void* args);
	virtual void threadedWork() = 0;

	virtual void printStartMessage() = 0;
	virtual void printStopMessage() = 0;

	HANDLE m_hThread = INVALID_HANDLE_VALUE;
	HANDLE m_hStopEvent = INVALID_HANDLE_VALUE;
	unsigned int m_ThreadId = 0;
	int m_CheckInterval = 1;
};