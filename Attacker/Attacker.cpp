#include <Windows.h>
#include <iostream>

int main()
{
	std::cout << "Attacker is running for 10 seconds";
	Sleep(10000);
	std::cout << "Attacker is exiting";
}