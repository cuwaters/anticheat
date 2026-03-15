#include <stdio.h>
#include "HashComparison.h"
#include <string>
#include <iostream>

const char* secretString = "This is a string";

int main(int argc, char* argv[])
{
    std::string input;
    std::cout << "Game is running.  Enter 'q' or 'Q' to exit." << std::endl;

    HashComparer* hasher = new HashComparer();
    hasher->Start();

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

    hasher->Stop();
    delete hasher;
    hasher = nullptr;
}
