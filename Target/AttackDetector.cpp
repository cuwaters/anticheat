#include "AttackDetector.h"
#include <process.h>
#include <iostream>

AttackDetector::AttackDetector(int checkInterval)
    : m_CheckInterval(checkInterval)
{
}

void AttackDetector::Start()
{
    m_hStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    m_hThread = (HANDLE)_beginthreadex(NULL, 0, &StaticThreadStart, this, 0, &m_ThreadId);
}

void AttackDetector::Stop()
{
    if (m_hStopEvent != INVALID_HANDLE_VALUE)
    {
        SetEvent(m_hStopEvent);
    }

    if (m_hThread != INVALID_HANDLE_VALUE)
    {
        WaitForSingleObject(m_hThread, INFINITE);

    }

    CloseHandle(m_hThread);
    m_hThread = INVALID_HANDLE_VALUE;

    CloseHandle(m_hStopEvent);
    m_hStopEvent = INVALID_HANDLE_VALUE;
}

unsigned __stdcall AttackDetector::StaticThreadStart(void* args)
{
    AttackDetector* pThis = static_cast<AttackDetector*>(args);

    if (nullptr != pThis)
    {
        pThis->printStartMessage();
        while (WaitForSingleObject(pThis->m_hStopEvent, 1) == WAIT_TIMEOUT) // Check to see if we've been signaled to stop.  If not, we'll timeout on the wait, otherwise we'll get a success code
        {
            pThis->threadedWork();
            Sleep(pThis->m_CheckInterval);
        }
        pThis->printStopMessage();
    }
    return 0;
}

void AttackDetector::attackDetected(int attackCode)
{
    std::cout << "Attack detected! Code is 0x" << std::hex << std::uppercase << attackCode << "\r\n";
    std::cout << "Process exiting, you dirty cheater\r\n";

    exit(attackCode);
}