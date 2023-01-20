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
* This file is the starting point of the program
* It allows the user to work with files and apply the hashing algorithm to their contents
*
*/

#include <fstream>
#include <iostream>

#include "Helpers.h"
#include "SHA256.h"

using namespace std;

unsigned int getMin(unsigned int first, unsigned int second)
{
	return first > second ? second : first;
}

// Reads a string with a given amount from file
// If the file doesn't have that many characters, updates the characters to read count
char* readFromFile(const char* path, size_t charsToRead)
{
	ifstream inputFile;
	inputFile.open(path);

	char* text = nullptr;
	if (inputFile.is_open())
	{
		inputFile.seekg(0, ios::end);
		size_t fileSize = (size_t)inputFile.tellg();
		inputFile.seekg(0, ios::beg);

		size_t requiredSize = getMin(fileSize, charsToRead);

		text = new char[requiredSize + 1];
		inputFile.read(text, requiredSize);
		text[requiredSize] = '\0';
	}

	inputFile.close();

	return text;
}

// Writes a given text result to a file
bool writeInFile(const char* path, const char* text)
{
	ofstream outputFile;
	outputFile.open(path, ios::trunc);
	bool result = true;

	if (outputFile.is_open())
	{
		outputFile.write(text, getLength(text));
	}
	else
	{
		result = false;
	}

	outputFile.close();
	return result;
}

// Checks whether two texts are identical
bool areTextsEqual(const char* firstText, const char* secondText)
{
	while (*firstText == *secondText)
	{
		if (*firstText == '\0')
		{
			return true;
		}

		firstText++;
		secondText++;
	}

	return false;
}

char getUpper(char symbol)
{
	const char DIFFERENCE = 'A' - 'a';

	if (symbol >= 'a' && symbol <= 'z')
	{
		return symbol + DIFFERENCE;
	}

	return symbol;
}

// Checks whether a substring is a suffix to another string
bool isSuffix(const char* text, const char* suffix, size_t suffixLength)
{
	size_t length = getLength(text);

	if (length < suffixLength)
	{
		return false;
	}

	for (int i = suffixLength - 1; i >= 0; i--)
	{
		if (suffix[i] != text[length - suffixLength + i])
		{
			return false;
		}
	}

	return true;
}

// Validates whether the given file is a text document
bool validateTextPath(const char* path)
{
	const size_t EXTENTION_LENGTH = 4;
	const char* TEXT_FILE_EXTENTION = ".txt";

	return isSuffix(path, TEXT_FILE_EXTENTION, EXTENTION_LENGTH);
}

// Reads a file path
void inputFileSequence(char* path, size_t size)
{
	cout << "Please, input a text file path, which is less than " << size + 1 << " symbols:" << endl;
	cout << "(Example: input.txt)" << endl;

	cin.getline(path, size);
}

// Hashes the text from a given file
char* hashFromFile(const char* path, size_t symbols)
{
	char* fileText = readFromFile(path, symbols);
	char* result = hashMessage(fileText);
	delete[] fileText;

	return result;
}

// Console Hash command sequence of operations
void hashSequence(const char* hash)
{
	const char EXIT_KEY = '0';
	const char* OUTPUT_PATH = "output.txt";

	cout << "Hash result:" << endl;
	cout << hash << endl;

	cout << "Would you like to save the hash?" << endl;
	cout << "0 - Don't save and restart program" << endl;
	cout << "Any other key - Save to " << OUTPUT_PATH << endl;

	char input = 0;
	cin >> input;
	if (input == EXIT_KEY)
	{
		return;
	}

	bool success = writeInFile(OUTPUT_PATH, hash);
	if (!success)
	{
		cout << "An error has occured!" << endl;
	}
	else
	{
		cout << "File has been saved!" << endl;
	}
}

// Console Compare command sequence of operations
void compareSequence(const char* hash)
{
	const size_t HASH_SIZE = 64;
	char hashInput[HASH_SIZE + 1] = "";
	cout << "Please, enter a comparison hash" << endl;
	cin.getline(hashInput, HASH_SIZE + 1);

	bool isMatching = areTextsEqual(hash, hashInput);
	if (isMatching)
	{
		cout << "The message matches the given hash" << endl;
	}
	else
	{
		cout << "The hashes don't match" << endl;
	}
}

// Initial sequence for any operation
void initiateSequence(void (*sequence)(const char* hash))
{
	const size_t PATH_MAX_SIZE = 256;

	char path[PATH_MAX_SIZE] = "";
	inputFileSequence(path, PATH_MAX_SIZE - 1);

	if (validateTextPath(path))
	{
		size_t symbolsToRead = 0;
		cout << "Please enter how many symbols would you like to read from this file:" << endl;
		cout << "(Enter -1 if you want to read the whole file)" << endl;
		cin >> symbolsToRead;
		cin.ignore();

		char* result = hashFromFile(path, symbolsToRead);

		sequence(result);

		delete[] result;
	}
	else
	{
		cout << "Invalid Path!" << endl;
		return;
	}
}

int main()
{
	const char EXIT_COMMAND = 'E';
	const char HASH_COMMAND = 'H';
	const char COMPARE_COMMAND = 'C';

	char input = 0;
	do
	{
		cout << "Type one of the following commands:" << endl;
		cout << "H - hash a file" << endl;
		cout << "C - compare a file's text with a hash" << endl;
		cout << "E - exit" << endl;

		cin >> input;
		cin.ignore();

		input = getUpper(input);

		if (input == HASH_COMMAND)
		{
			initiateSequence(hashSequence);
		}
		else if (input == COMPARE_COMMAND)
		{
			initiateSequence(compareSequence);
		}
		else if (input != EXIT_COMMAND)
		{
			cout << "ERROR: Unregistered command!" << endl;
		}
		cout << "===================================" << endl;
	} while (input != EXIT_COMMAND);
}