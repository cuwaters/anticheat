#include <stdio.h>
#include "IAttackDetector.h"
#include "HashComparison.h"
#include <string>
#include <iostream>
#include <vector>

const char* secretString = "This is a string";

int main(int argc, char* argv[])
{
    std::string input;
    std::cout << "Game is running.  Enter 'q' or 'Q' to exit." << std::endl;

    std::vector<AttackDetector*> attackDetectors;

    attackDetectors.push_back(new HashComparer());

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

    std::cout << "Application exiting gracefully" << std::endl;

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
}
