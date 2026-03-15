#pragma once
#include <Windows.h>

class AttackDetector
{
public:
	virtual void Start();
	virtual void Stop();
protected:
	static unsigned __stdcall StaticThreadStart(void* args);
	virtual void threadedWork() = 0;
	virtual int getCheckInterval() = 0;

	HANDLE m_hThread = INVALID_HANDLE_VALUE;
	HANDLE m_hStopEvent = INVALID_HANDLE_VALUE;
	unsigned int m_ThreadId = 0;
};