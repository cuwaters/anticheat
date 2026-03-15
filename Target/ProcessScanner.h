#pragma once
#include "AttackDetector.h"

class ProcessScanner : public AttackDetector
{
public: 
	ProcessScanner();
private:
    /* AttackDetector implementation */
    void threadedWork() override;
    void printStartMessage() override;
    void printStopMessage() override; 
};