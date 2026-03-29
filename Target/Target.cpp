#include <stdio.h>
#include <string>
#include <iostream>
#include <vector>


#include "AttackDetector.h"
#include "HashComparison.h"
#include "ProcessScanner.h"
#include "MemoryTamperScanner.h"


const char secretString[] = "This is a string in .text section";

int main(int argc, char* argv[])
{
    std::string input;
    std::cout << "Game is running.  Enter 'q' or 'Q' to exit." << std::endl;

    std::cout << "this is the string that will be attacked:" << std::endl << secretString << std::endl;

    std::vector<AttackDetector*> attackDetectors;

    attackDetectors.push_back(new HashComparer());
    attackDetectors.push_back(new ProcessScanner());
    //attackDetectors.push_back(new MemoryTamperScanner()); // too many false positives

    for (AttackDetector* detector : attackDetectors)
    {
        detector->Start();
    }

    while (true)
    {
        // keep the 'game' running
        std::getline(std::cin, input);
        if (input == "q" || input == "Q")
        {
            break;
        }
    }

    for (auto curr = attackDetectors.begin(); curr != attackDetectors.end(); ++curr)
    {
        // grab the current pointer out of the iterator
        AttackDetector* detector = *curr;

        // stop the detector and free it's memory
        detector->Stop();
        delete detector;
    }
    // this leaves a freed pointers in the vector, it's no longer safe to interact with any elements, so clear them all
    attackDetectors.clear();

    std::cout << "Application exiting gracefully" << std::endl;
}
