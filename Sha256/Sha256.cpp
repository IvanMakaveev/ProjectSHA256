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
* This file contains the logic of the hashing algorithm and all of its constants and settings
*
*/

#include "Helpers.h"
#include "SHA256.h"

using namespace std;

typedef unsigned char byte;
typedef unsigned int word32;

const size_t BYTE_SIZE = 8;
const size_t WORD_SIZE = 32;
const size_t HEX_IN_BYTE = 4;
const size_t RESULT_WORDS_COUNT = 8;
const size_t SCHEDULE_WORDS_COUNT = 64;
const size_t MESSAGE_BLOCK_SIZE = 512;

const size_t BYTES_IN_WORD = WORD_SIZE / BYTE_SIZE;
const size_t WORD_HEX_SIZE = WORD_SIZE / HEX_IN_BYTE;
const size_t MESSAGE_BLOCK_BYTES = MESSAGE_BLOCK_SIZE / BYTE_SIZE;
const size_t MESSAGE_BLOCK_WORDS = MESSAGE_BLOCK_SIZE / WORD_SIZE;

// The default K-constants for the SHA256 algorithm
const word32 CUBE_ROOT_CONSTANTS[64] =
{
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

// The initial state registers for the SHA256 algorithm
const word32 INITIAL_HASH_VALUES[RESULT_WORDS_COUNT] =
{
	0x6a09e667,
	0xbb67ae85,
	0x3c6ef372,
	0xa54ff53a,
	0x510e527f,
	0x9b05688c,
	0x1f83d9ab,
	0x5be0cd19
};

// The names of each state register and its corresponding value
enum HashValueNames
{
	a = 0,
	b = 1,
	c = 2,
	d = 3,
	e = 4,
	f = 5,
	g = 6,
	h = 7
};

/* 
	Validation functions
*/
bool isValidHashSize(size_t size)
{
	return size == RESULT_WORDS_COUNT;
}

bool isValidMessageBlock(size_t size)
{
	return size == MESSAGE_BLOCK_BYTES;
}

bool isValidSchedule(size_t size)
{
	return size == SCHEDULE_WORDS_COUNT;
}

bool isNullPointer(const byte* ptr)
{
	return ptr == nullptr;
}

bool isNullPointer(const word32* ptr)
{
	return ptr == nullptr;
}

bool isNullPointer(const char* ptr)
{
	return ptr == nullptr;
}

/*
	Bitwise operation functions
*/

// Validates whether the given position offset is within type size
word32 getValidPositions(unsigned int positions)
{
	return positions % WORD_SIZE;
}

// Performs a bitwise right shift on a word
word32 shift(word32 word, unsigned int positions)
{
	positions = getValidPositions(positions);

	return word >> positions;
}

// Performs a bitwise right rotation on a word
word32 rotate(word32 word, unsigned int positions)
{
	positions = getValidPositions(positions);

	word32 primaryShift = word >> positions;
	word32 excessShift = word << (WORD_SIZE - positions);

	return primaryShift | excessShift;
}

// Performs bitwise addition to an array of words
word32 add(const word32* words, size_t size)
{
	word32 result = 0;

	for (size_t i = 0; i < size; i++)
	{
		result += words[i];
	}

	return result;
}

// Performs a bitwise majority operation
// Each bit is decided by the value that has more presense in the input words
word32 majority(word32 firstWord, word32 secondWord, word32 thirdWord)
{
	return (firstWord & secondWord) | (secondWord & thirdWord) | (thirdWord & firstWord);
}

// Performs a bitwise choose operation
// Each bit is decided by a mask word and the corresponding bit in the first or second words
word32 choose(word32 maskWord, word32 firstWord, word32 secondWord)
{
	return (maskWord & firstWord) ^ (~maskWord & secondWord);
}

// A general lower sigma function - performs two rotations and a shift, connected with XORs
word32 lowerSigma(word32 word, const byte* operationValues, size_t size)
{
	const size_t OPERATIONS_COUNT = 3;
	if (size != OPERATIONS_COUNT)
	{
		return word;
	}

	word32 result =
		rotate(word, operationValues[0]) ^
		rotate(word, operationValues[1]) ^
		shift(word, operationValues[2]);

	return result;
}

// A general upper sigma function - performs three rotations, connected with XORs
word32 upperSigma(word32 word, const byte* operationValues, size_t size)
{
	const size_t OPERATIONS_COUNT = 3;
	if (size != OPERATIONS_COUNT)
	{
		return word;
	}

	word32 result =
		rotate(word, operationValues[0]) ^
		rotate(word, operationValues[1]) ^
		rotate(word, operationValues[2]);

	return result;
}

// A concrete lower sigma zero bitwise function with constant parameters
word32 lowerSigmaZero(word32 word)
{
	const byte LOWER_SIGMA_ZERO_OPERATIONS[] = { 7, 18, 3 };
	return lowerSigma(word, LOWER_SIGMA_ZERO_OPERATIONS, 3);
}

// A concrete lower sigma one bitwise function with constant parameters
word32 lowerSigmaOne(word32 word)
{
	const byte LOWER_SIGMA_ONE_OPERATIONS[] = { 17, 19, 10 };
	return lowerSigma(word, LOWER_SIGMA_ONE_OPERATIONS, 3);
}

// A concrete upper sigma zero bitwise function with constant parameters
word32 upperSigmaZero(word32 word)
{
	const byte UPPER_SIGMA_ZERO_OPERATIONS[] = { 2, 13, 22 };
	return upperSigma(word, UPPER_SIGMA_ZERO_OPERATIONS, 3);
}

// A concrete upper sigma one bitwise function with constant parameters
word32 upperSigmaOne(word32 word)
{
	const byte UPPER_SIGMA_ONE_OPERATIONS[] = { 6, 11, 25 };
	return upperSigma(word, UPPER_SIGMA_ONE_OPERATIONS, 3);
}

/*
	Message creation and padding functions
*/

// Calculates the total size of the padded message
size_t getTotalRequiredSize(size_t messageSize, size_t endPaddingSize)
{
	size_t currentSize = messageSize + endPaddingSize + 1;
	unsigned int fullBlocks = currentSize / MESSAGE_BLOCK_BYTES;
	unsigned int extraBits = currentSize % MESSAGE_BLOCK_BYTES;

	return (fullBlocks + (extraBits != 0)) * MESSAGE_BLOCK_BYTES;
}

// Fills the padded message with the initial message bytes
void fillInitialMessage(const byte* initialMessage, byte* paddedMessage, size_t initialSize, size_t paddedSize)
{
	if (initialSize > paddedSize || isNullPointer(initialMessage) || isNullPointer(paddedMessage))
	{
		return;
	}

	for (size_t i = 0; i < initialSize; i++)
	{
		paddedMessage[i] = initialMessage[i];
	}
}

// Appends a padding one separator byte to the message
void appendPaddingOne(byte* paddedMessage, size_t initialSize, size_t paddedSize)
{
	if (initialSize + 1 > paddedSize || isNullPointer(paddedMessage))
	{
		return;
	}

	const byte PADDING_ONE = 0b10000000;

	paddedMessage[initialSize] = PADDING_ONE;
}

// Pads the message with zeros
void padWithZeros(byte* paddedMessage, size_t initialSize, size_t paddedSize, size_t initialSizeBytes)
{
	size_t zerosToPad = paddedSize - (initialSize + initialSizeBytes + 1);

	if (initialSize + zerosToPad >= paddedSize || isNullPointer(paddedMessage))
	{
		return;
	}

	size_t endIndex = initialSize + zerosToPad;
	for (size_t i = initialSize + 1; i <= endIndex; i++)
	{
		paddedMessage[i] = 0;
	}
}

// Initializes a given byte array with a given value
void initializeBytes(byte* bytes, size_t size, byte initalValue)
{
	if (isNullPointer(bytes))
	{
		return;
	}

	for (size_t i = 0; i < size; i++)
	{
		bytes[i] = initalValue;
	}
}

// Creates and returns an array of bytes, representing the given size value
byte* getInitialSizeBytes(size_t initialSize, size_t sizeBytesCount)
{
	byte* result = new byte[sizeBytesCount];
	initializeBytes(result, sizeBytesCount, 0);

	initialSize *= BYTE_SIZE;

	unsigned int index = 0;
	unsigned int counterOfOperations = 0;
	while (initialSize != 0)
	{
		byte multiplier = (1 << counterOfOperations++);
		result[index] += initialSize % 2 * multiplier;
		initialSize /= 2;
		if (counterOfOperations == BYTE_SIZE)
		{
			index++;
			counterOfOperations = 0;
		}
	}

	return result;
}

// Appends the given initial size as bytes to the end of the padded message
void appendInitialSize(byte* paddedMessage, size_t initialSize, size_t paddedSize, size_t sizeBytesCount)
{
	if (isNullPointer(paddedMessage))
	{
		return;
	}

	byte* initalSizeBytes = getInitialSizeBytes(initialSize, sizeBytesCount);
	if (isNullPointer(initalSizeBytes))
	{
		return;
	}

	for (size_t i = 0; i < sizeBytesCount; i++)
	{
		paddedMessage[paddedSize - i - 1] = initalSizeBytes[i];
	}

	delete[] initalSizeBytes;
}

// Creates the total message with its padding
void createMessage(const byte* initialMessage, size_t size, byte*& paddedMessage, size_t& totalSize)
{
	if (paddedMessage != nullptr)
	{
		return;
	}

	const size_t INITIAL_SIZE_BYTES = 2;
	totalSize = getTotalRequiredSize(size, INITIAL_SIZE_BYTES);

	paddedMessage = new byte[totalSize];
	fillInitialMessage(initialMessage, paddedMessage, size, totalSize);
	appendPaddingOne(paddedMessage, size, totalSize);
	padWithZeros(paddedMessage, size, totalSize, INITIAL_SIZE_BYTES);
	appendInitialSize(paddedMessage, size, totalSize, INITIAL_SIZE_BYTES);
}

/*
	Hashing algorithm functions
*/

// Initialization function for the hash state registers
void initializeWords(word32* words, size_t size)
{
	if (!isValidHashSize(size) || isNullPointer(words))
	{
		return;
	}

	for (size_t i = 0; i < size; i++)
	{
		words[i] = INITIAL_HASH_VALUES[i];
	}
}

// A conversion function for turning bytes into a 32 bit word
word32 getWordFromBytes(const byte* bytes, size_t wordBytes)
{
	if (isNullPointer(bytes))
	{
		return 0;
	}

	word32 result = 0;

	for (size_t i = 0; i < wordBytes; i++)
	{
		unsigned int multiplier = (1 << ((wordBytes - i - 1) * BYTE_SIZE));
		result += bytes[i] * multiplier;
	}

	return result;
}

// Fills the initial message schedule with the message block's words
void fillInitialSchedule(const byte* messageBlock, size_t blockBytes, word32* schedule, size_t scheduleSize)
{
	if (!isValidSchedule(scheduleSize) || 
		!isValidMessageBlock(blockBytes) ||
		isNullPointer(messageBlock) ||
		isNullPointer(schedule))
	{
		return;
	}

	for (size_t i = 0; i < MESSAGE_BLOCK_WORDS; i++)
	{
		schedule[i] = getWordFromBytes(messageBlock + i * BYTES_IN_WORD, BYTES_IN_WORD);
	}
}

// Generates the remaining message schedule words given a pre-determined algorithm of sigma additions
void generateScheduleValues(word32* schedule, size_t scheduleSize)
{
	if (!isValidSchedule(scheduleSize) || isNullPointer(schedule))
	{
		return;
	}

	const size_t COMPONENTS_COUNT = 4;
	for (size_t i = MESSAGE_BLOCK_WORDS; i < scheduleSize; i++)
	{
		word32 components[COMPONENTS_COUNT] =
		{
			lowerSigmaOne(schedule[i - 2]),
			schedule[i - 7],
			lowerSigmaZero(schedule[i - 15]),
			schedule[i - 16]
		};

		schedule[i] = add(components, COMPONENTS_COUNT);
	}
}

// Generates the T1 temporary word used for hashing
word32 getFirstTempWord(word32 messageWord, word32 constantWord, const word32* resultHash, size_t resultHashSize)
{
	if (!isValidHashSize(resultHashSize) || isNullPointer(resultHash))
	{
		return 0;
	}

	const size_t COMPONENTS_COUNT = 5;
	word32 components[COMPONENTS_COUNT] =
	{
		upperSigmaOne(resultHash[e]),
		choose(resultHash[e], resultHash[f], resultHash[g]),
		resultHash[h],
		constantWord,
		messageWord
	};

	return add(components, COMPONENTS_COUNT);
}

// Generates the T2 temporary word used for hashing
word32 getSecondTempWord(const word32* resultHash, size_t resultHashSize)
{
	if (!isValidHashSize(resultHashSize) || isNullPointer(resultHash))
	{
		return 0;
	}

	const size_t COMPONENTS_COUNT = 2;
	word32 components[COMPONENTS_COUNT] =
	{
		upperSigmaZero(resultHash[a]),
		majority(resultHash[a], resultHash[b], resultHash[c]),
	};

	return add(components, COMPONENTS_COUNT);
}

// Moves each state register value up an index (last one is lost)
void moveResultHashes(word32* resultHash, size_t resultHashSize)
{
	if (!isValidHashSize(resultHashSize) || isNullPointer(resultHash))
	{
		return;
	}

	for (size_t i = resultHashSize - 1; i >= 1; i--)
	{
		resultHash[i] = resultHash[i - 1];
	}
}

// Copies an input byte array into an output byte array
void createCopies(const word32* inputWords, size_t inputSize, word32* wordCopies, size_t sizeCopies)
{
	if (sizeCopies != inputSize || isNullPointer(inputWords) || isNullPointer(wordCopies))
	{
		return;
	}

	for (size_t i = 0; i < sizeCopies; i++)
	{
		wordCopies[i] = inputWords[i];
	}
}

// Hashes a given message block
// It generates a message schedule that is used to update the state registers with T1 and T2 temporary words
// At the end adds each of the inital values to the state register's current values
void hashMessageBlock(const byte* messageBlock, size_t blockBytes, word32* resultHash, size_t resultHashSize)
{
	if (!isValidHashSize(resultHashSize) || 
		!isValidMessageBlock(blockBytes) ||
		isNullPointer(messageBlock) ||
		isNullPointer(resultHash))
	{
		return;
	}

	word32 messageSchedule[SCHEDULE_WORDS_COUNT] = { 0 };

	fillInitialSchedule(messageBlock, blockBytes, messageSchedule, SCHEDULE_WORDS_COUNT);
	generateScheduleValues(messageSchedule, SCHEDULE_WORDS_COUNT);

	word32 resultCopies[RESULT_WORDS_COUNT] = { 0 };
	createCopies(resultHash, resultHashSize, resultCopies, RESULT_WORDS_COUNT);

	for (size_t i = 0; i < SCHEDULE_WORDS_COUNT; i++)
	{
		word32 firstTempWord = getFirstTempWord(
			messageSchedule[i], 
			CUBE_ROOT_CONSTANTS[i], 
			resultHash, 
			resultHashSize);

		word32 secondTempWord = getSecondTempWord(
			resultHash, 
			resultHashSize);

		moveResultHashes(resultHash, resultHashSize);
		resultHash[a] = firstTempWord + secondTempWord;
		resultHash[e] += firstTempWord;
	}

	for (size_t i = 0; i < resultHashSize; i++)
	{
		resultHash[i] += resultCopies[i];
	}
}

// Converts a given value to hexadecimal character
char toHexChar(unsigned int value)
{
	const unsigned short HEX_BASE = 16;
	value = value % HEX_BASE;
	if (value < 10)
	{
		return value + '0';
	}
	else
	{
		return value - 10 + 'a';
	}
}

// Fills a given word as hexadecimal characters to a string
void fillCharsFromWordHex(char* charOut, size_t size, word32 word)
{
	if (isNullPointer(charOut) || size < WORD_HEX_SIZE)
	{
		return;
	}

	int counter = WORD_HEX_SIZE - 1;
	unsigned int mask = (1 << HEX_IN_BYTE);
	while (counter >= 0)
	{
		charOut[counter] = toHexChar(word % mask);
		word /= mask;
		counter--;
	}
}

// Creates a hash text from the hexadecimal values of the given words
char* getTextFromWords(const word32* text, size_t size)
{
	if (isNullPointer(text))
	{
		return nullptr;
	}

	size_t resultSize = WORD_HEX_SIZE * size;
	char* result = new char[resultSize + 1];

	for (size_t i = 0; i < size; i++)
	{
		fillCharsFromWordHex(result + i * WORD_HEX_SIZE, WORD_HEX_SIZE, text[i]);
	}
	result[resultSize] = '\0';

	return result;
}

// Creates a byte array from a given string
byte* getTextBytes(const char* text, size_t size)
{
	if (isNullPointer(text))
	{
		return nullptr;
	}

	byte* result = new byte[size];

	for (size_t i = 0; i < size; i++)
	{
		result[i] = text[i];
	}

	return result;
}

// Hashes a given string
// The string is converted to bytes which are used for message creation
// The message is split into blocks of 512 bits that are fed to the hashing algorithm
// Returns a string of the final hash result
char* hashMessage(const char* initialMessage)
{
	size_t size = getLength(initialMessage);
	byte* initialMessageBytes = getTextBytes(initialMessage, size);

	size_t totalMessageSize = 0;
	byte* totalMessage = nullptr;

	createMessage(initialMessageBytes, size, totalMessage, totalMessageSize);
	size_t messageBlocksCount = totalMessageSize / MESSAGE_BLOCK_BYTES;

	delete[] initialMessageBytes;

	word32 hashResult[RESULT_WORDS_COUNT] = { 0 };
	initializeWords(hashResult, RESULT_WORDS_COUNT);

	for (size_t i = 0; i < messageBlocksCount; i++)
	{
		hashMessageBlock(
			totalMessage + i * MESSAGE_BLOCK_BYTES, 
			MESSAGE_BLOCK_BYTES, 
			hashResult, 
			RESULT_WORDS_COUNT);
	}

	delete[] totalMessage;

	char* resultText = getTextFromWords(hashResult, RESULT_WORDS_COUNT);
	return resultText;
}