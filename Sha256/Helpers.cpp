/**
*
* Solution to course project # 6
* Introduction to programming course
* Faculty of Mathematics and Informatics of Sofia University
* Winter semester 2022/2023
*
* @author Ivan Emanuilov Makaveev
* @idnumber 2MI0600203
* @compiler VC
*
* This file contains definitions of helper functions used by the other project files
*
*/


#include "Helpers.h"

// Returns the length of a given string
size_t getLength(const char* text)
{
	if (text == nullptr)
	{
		return 0;
	}

	size_t counter = 0;
	while (*text)
	{
		counter++;
		text++;
	}

	return counter;
}