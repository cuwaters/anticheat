#pragma once
#include <Windows.h>
#include <chrono>
#include <string>

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
	void printDurationMessage(std::string prependStr);

	__forceinline void startDetectionTimer() { m_StartTime = std::chrono::high_resolution_clock::now(); }
	__forceinline void stopDetectionTimer() { m_EndTime = std::chrono::high_resolution_clock::now(); }

	virtual void attackDetected(int attackCode);

	HANDLE m_hThread = INVALID_HANDLE_VALUE;
	HANDLE m_hStopEvent = INVALID_HANDLE_VALUE;
	unsigned int m_ThreadId = 0;
	int m_CheckInterval = 1;
	std::chrono::high_resolution_clock::time_point m_StartTime;
	std::chrono::high_resolution_clock::time_point m_EndTime;
};