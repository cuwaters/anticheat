#include "IAttackDetector.h"
#include <process.h>

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
        while (WaitForSingleObject(pThis->m_hStopEvent, 1) == WAIT_TIMEOUT) // Check to see if we've been signaled to stop.  If not, we'll timeout on the wait, otherwise we'll get a success code
        {
            pThis->threadedWork();
            Sleep(pThis->getCheckInterval());
        }
    }
    return 0;
}