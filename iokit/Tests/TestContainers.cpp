/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
#if DEBUG
#include "Tests.h"

#include <libkern/c++/OSData.h>
#include <libkern/c++/OSString.h>
#include <libkern/c++/OSSymbol.h>

static const char testC00[] = "The quick brown fox jumps over the lazy dog.  ";
static const char testC01[] = "The quick brown fox ";
static const char testC02[] = "jumps over the ";
static const char testC03[] = "lazy dog.  \n";
static const char testC04[] = "The ";
static const char testC05[] = "quick ";
static const char testC06[] = "brown ";
static const char testC07[] = "fox ";
static const char testC08[] = "jumps ";
static const char testC09[] = "over ";
static const char testC10[] = "the ";
static const char testC11[] = "lazy ";
static const char testC12[] = "dog.  \n";
static const char testC13[] = "Now is the time for all good "
    "men to come to the aid of the party  \n";
static const char testC14[] = "Now is the time for ";
static const char testC15[] = "all good men to come ";
static const char testC16[] = "to the aid of the party  \n";
static const char testC17[] = "Now ";
static const char testC18[] = "is ";
static const char testC19[] = "the ";
static const char testC20[] = "time ";
static const char testC21[] = "for ";
static const char testC22[] = "all ";
static const char testC23[] = "good ";
static const char testC24[] = "men ";
static const char testC25[] = "to ";
static const char testC26[] = "come ";
static const char testC27[] = "to ";
static const char testC28[] = "the ";
static const char testC29[] = "aid ";
static const char testC30[] = "of ";
static const char testC31[] = "the ";
static const char testC32[] = "party.  \n";
static const char testC33[] = "Frank Burns eats worms.  \n";
static const char testC34[] = "Frank Burns ";
static const char testC35[] = "eats worms.  \n";
static const char testC36[] = "Frank ";
static const char testC37[] = "Burns ";
static const char testC38[] = "eats ";
static const char testC39[] = "worms.  \n";
static const char testC40[] = "Tired eyes?  Stiff neck?  Tight shoulders?  "
    "Aching back?  The right moves can help "
    "prevent these kinds of problem.  ";
static const char testC41[] = "Tired eyes?  Stiff neck?  ";
static const char testC42[] = "Tight shoulders?  Aching back?  ";
static const char testC43[] = "The right moves can help prevent ";
static const char testC44[] = "these kinds of problem.  ";
static const char testC45[] = "Tired ";
static const char testC46[] = "eyes?  ";
static const char testC47[] = "Stiff ";
static const char testC48[] = "neck?  ";
static const char testC49[] = "Tight ";
static const char testC50[] = "shoulders?  ";
static const char testC51[] = "Aching ";
static const char testC52[] = "back?  ";
static const char testC53[] = "The ";
static const char testC54[] = "right ";
static const char testC55[] = "moves ";
static const char testC56[] = "can ";
static const char testC57[] = "help ";
static const char testC58[] = "prevent ";
static const char testC59[] = "these ";
static const char testC60[] = "kinds ";
static const char testC61[] = "of ";
static const char testC62[] = "problem.  ";

const char *strCache[] = {
	testC00, testC01, testC02, testC03, testC04, testC05, testC06, testC07,
	testC08, testC09, testC10, testC11, testC12, testC13, testC14, testC15,
	testC16, testC17, testC18, testC19, testC20, testC21, testC22, testC23,
	testC24, testC25, testC26, testC27, testC28, testC29, testC30, testC31,
	testC32, testC33, testC34, testC35, testC36, testC37, testC38, testC39,
	testC40, testC41, testC42, testC43, testC44, testC45, testC46, testC47,
	testC48, testC49, testC50, testC51, testC52, testC53, testC54, testC55,
	testC56, testC57, testC58, testC59, testC60, testC61, testC62,
};
const int numStrCache = ((int) (sizeof(strCache) / sizeof(strCache[0])));

void
testData()
{
#define DATA_SIZE_1      256
#define DATA_SIZE_2      512
#define DATA_SIZE_3     1024
#define DATA_SIZE_4     8192

	OSData *test1, *test2, *test3;
	void *spaceCheck;
	unsigned int len;
	unsigned int i;
	bool res = true;
	unsigned short testData[DATA_SIZE_4 / sizeof(short)], *cp;

	// very first test initialises the OSMetaClass cache.
	test1 = OSData::withCapacity(DATA_SIZE_1);
	TEST_ASSERT('d', "0a", test1);
	if (test1) {
		test1->release();
	}

	for (i = 0; i < sizeof(testData) / sizeof(short); i++) {
		testData[i] = (unsigned short) i;
	}

	// Check empty data allocation
	spaceCheck = checkPointSpace();
	test1 = OSData::withCapacity(DATA_SIZE_1);
	TEST_ASSERT('d', "1a", test1);
	if (test1) {
		TEST_ASSERT('d', "1b", !test1->getLength());
		TEST_ASSERT('d', "1c", test1->getCapacity() == DATA_SIZE_1);
		TEST_ASSERT('d', "1d", !test1->getBytesNoCopy());
		TEST_ASSERT('d', "1e", !test1->getBytesNoCopy(10, DATA_SIZE_1 - 10));
		TEST_ASSERT('d', "1f", test1->appendBytes(spaceCheck, 0));
		TEST_ASSERT('d', "1g", !test1->getLength());
		TEST_ASSERT('d', "1h", test1->getCapacity() == DATA_SIZE_1);
		TEST_ASSERT('d', "1i", !test1->getBytesNoCopy());
		test1->release();
	}
	res = res && checkSpace("(d)1", spaceCheck, 0);

	// Check appending to empty data allocation
	spaceCheck = checkPointSpace();
	test1 = OSData::withCapacity(DATA_SIZE_1);
	TEST_ASSERT('d', "2a", test1);
	if (test1) {
		TEST_ASSERT('d', "2b", !test1->getLength());
		TEST_ASSERT('d', "2c", !test1->getBytesNoCopy());
		TEST_ASSERT('d', "2d", test1->appendBytes(testData, DATA_SIZE_1));
		TEST_ASSERT('d', "2e", test1->getLength() == DATA_SIZE_1);
		TEST_ASSERT('d', "2f", test1->getBytesNoCopy());
		cp = (unsigned short *) test1->getBytesNoCopy();
		for (i = 0; cp && i < (DATA_SIZE_1 / sizeof(short)); i++) {
			TEST_ASSERT('d', "2g", *cp++ == testData[i]);
			if (*cp != testData[i]) {
				break;
			}
		}
		TEST_ASSERT('d', "2h", test1->getBytesNoCopy(10, DATA_SIZE_1 - 10));
		cp = (unsigned short *) test1->getBytesNoCopy(10, DATA_SIZE_1 - 10);
		for (i = 5; cp && i < (DATA_SIZE_1 / sizeof(short)) - 5; i++) {
			TEST_ASSERT('d', "2i", *cp++ == testData[i]);
			if (*cp != testData[i]) {
				break;
			}
		}
		TEST_ASSERT('d', "2j", test1->isEqualTo(testData, DATA_SIZE_1));
		test1->release();
	}
	res = res && checkSpace("(d)2", spaceCheck, 0);

	// Check data allocation from some constant data
	spaceCheck = checkPointSpace();
	test1 = OSData::withBytes(testData, sizeof(testData));
	TEST_ASSERT('d', "3a", test1);
	if (test1) {
		TEST_ASSERT('d', "3b", test1->getLength() == sizeof(testData));
		TEST_ASSERT('d', "3c", test1->getCapacity() == sizeof(testData));
		TEST_ASSERT('d', "3d", test1->getBytesNoCopy());
		TEST_ASSERT('d', "3e", test1->getBytesNoCopy(10, sizeof(testData) - 10));
		TEST_ASSERT('d', "3f", test1->appendBytes(spaceCheck, 0));
		TEST_ASSERT('d', "3g", test1->getLength() == sizeof(testData));
		TEST_ASSERT('d', "3h", test1->getCapacity() == sizeof(testData));
		TEST_ASSERT('d', "3i", test1->getBytesNoCopy());
		TEST_ASSERT('d', "3j", test1->getBytesNoCopy(10, sizeof(testData) - 10));
		TEST_ASSERT('d', "3k", !test1->appendBytes(testData, 10));
		test1->release();
	}
	res = res && checkSpace("(d)3", spaceCheck, 0);

	// Check and continious addition of more data
	spaceCheck = checkPointSpace();
	test1 = OSData::withCapacity(DATA_SIZE_4);
	test2 = OSData::withBytesNoCopy(testData, DATA_SIZE_3);
	len = DATA_SIZE_3;
	TEST_ASSERT('d', "4a", (test1 && test2));
	if (test1 && test2) {
		TEST_ASSERT('d', "4b", !test1->getLength());
		for (i = 0; i < DATA_SIZE_4; i += DATA_SIZE_3) {
			TEST_ASSERT('d', "4c", test1->appendBytes(test2));
		}
		TEST_ASSERT('d', "4d", !test1->appendBytes(test2));
		for (i = 0; i < DATA_SIZE_4; i += DATA_SIZE_3) {
			TEST_ASSERT('d', "4e", test2->isEqualTo(
				    test1->getBytesNoCopy(i, DATA_SIZE_3),
				    DATA_SIZE_3));

			test3 = OSData::withData(test1, i, DATA_SIZE_3);
			TEST_ASSERT('d', "4f", test3);
			if (test3) {
				TEST_ASSERT('d', "4g", test2->isEqualTo(test3));
				test3->release();
			}

			test3 = OSData::withData(test1, i, len);
			TEST_ASSERT('d', "4i", test3);
			if (test3) {
				TEST_ASSERT('d', "4j", test2->isEqualTo(test3));
				test3->release();
			}
		}
		test1->release();
		test2->release();
	}
	res = res && checkSpace("(d)3", spaceCheck, 0);

	if (res) {
		verPrintf(("testData: All OSData Tests passed\n"));
	} else {
		logPrintf(("testData: Some OSData Tests failed\n"));
	}
#undef DATA_SIZE_4
#undef DATA_SIZE_3
#undef DATA_SIZE_2
#undef DATA_SIZE_1
}

void
testString()
{
	OSString *test1, *test2;
	void *spaceCheck;
	int i;
	char c;
	bool res = true;

	// very first test initialises the OSMetaClass cache.
	test1 = OSString::withCStringNoCopy(testC00);
	TEST_ASSERT('s', "0a", test1);
	if (test1) {
		test1->release();
	}

	// Check c string allocation
	spaceCheck = checkPointSpace();
	test1 = OSString::withCString(testC00);
	TEST_ASSERT('s', "1a", test1);
	TEST_ASSERT('s', "1b", testC00 != test1->getCStringNoCopy());
	TEST_ASSERT('s', "1c", strcmp(testC00, test1->getCStringNoCopy()) == 0);
	TEST_ASSERT('s', "1d", strlen(testC00) == test1->getLength());
	TEST_ASSERT('s', "1e", test1->isEqualTo(testC00));
	TEST_ASSERT('s', "1f", !test1->isEqualTo(testC01));
	if (test1) {
		test1->release();
	}
	res = res && checkSpace("(s)1", spaceCheck, 0);

	// Check c string no allocation
	spaceCheck = checkPointSpace();
	test1 = OSString::withCStringNoCopy(testC00);
	TEST_ASSERT('s', "2a", test1);
	TEST_ASSERT('s', "2b", testC00 == test1->getCStringNoCopy());
	if (test1) {
		test1->release();
	}
	res = res && checkSpace("(s)2", spaceCheck, 0);

	// Check string from other string generation
	spaceCheck = checkPointSpace();
	test1 = OSString::withCStringNoCopy(testC00);
	TEST_ASSERT('s', "3a", test1);
	test2 = OSString::withString(test1);
	TEST_ASSERT('s', "3b", test2);
	TEST_ASSERT('s', "3c", test1 != test2);
	TEST_ASSERT('s', "3d", test1->isEqualTo(test2));
	if (test1) {
		test1->release();
	}
	if (test2) {
		test2->release();
	}
	res = res && checkSpace("(s)3", spaceCheck, 0);

	// Check string comparison functionality no copy
	spaceCheck = checkPointSpace();
	test1 = OSString::withCStringNoCopy(testC00);
	test2 = OSString::withCStringNoCopy(testC01);
	TEST_ASSERT('s', "4a", test1 && test2);
	TEST_ASSERT('s', "4b", !test1->isEqualTo(test2));
	TEST_ASSERT('s', "4c", !test1->isEqualTo(testC01));
	TEST_ASSERT('s', "4d", test1->isEqualTo(testC00));
	if (test1) {
		test1->release();
	}
	if (test2) {
		test2->release();
	}
	res = res && checkSpace("(s)4", spaceCheck, 0);

	// Check string comparison functionality with copy
	spaceCheck = checkPointSpace();
	test1 = OSString::withCString(testC00);
	test2 = OSString::withCString(testC01);
	TEST_ASSERT('s', "5a", test1 && test2);
	TEST_ASSERT('s', "5b", !test1->isEqualTo(test2));
	TEST_ASSERT('s', "5c", !test1->isEqualTo(testC01));
	TEST_ASSERT('s', "5d", test1->isEqualTo(testC00));
	if (test1) {
		test1->release();
	}
	if (test2) {
		test2->release();
	}
	res = res && checkSpace("(s)5", spaceCheck, 0);

	// Check string inplace modifications
	spaceCheck = checkPointSpace();
	test1 = OSString::withCString(testC00);
	TEST_ASSERT('s', "6a", test1);
	for (i = 0; (c = test1->getChar(i)); i++) {
		if (c != testC00[i]) {
			verPrintf(("testString(s) test 6b failed\n")); res = false;
			break;
		}
	}
	TEST_ASSERT('s', "6c", !c);
	TEST_ASSERT('s', "6d", test1->setChar(' ', 0));
	TEST_ASSERT('s', "6e", !test1->isEqualTo(testC00));
	TEST_ASSERT('s', "6f", test1->setChar('T', 0));
	TEST_ASSERT('s', "6g", !test1->setChar(' ', sizeof(testC00)));
	TEST_ASSERT('s', "6h", test1->isEqualTo(testC00));
	if (test1) {
		test1->release();
	}
	res = res && checkSpace("(s)6", spaceCheck, 0);

	// Check const string fail inplace modifications
	spaceCheck = checkPointSpace();
	test1 = OSString::withCStringNoCopy(testC00);
	TEST_ASSERT('s', "7a", test1);
	for (i = 0; (c = test1->getChar(i)); i++) {
		if (c != testC00[i]) {
			verPrintf(("testString(s) test 7b failed\n")); res = false;
			break;
		}
	}
	TEST_ASSERT('s', "7c", !c);
	TEST_ASSERT('s', "7d", !test1->setChar(' ', 0));
	TEST_ASSERT('s', "7e", test1->isEqualTo(testC00));
	TEST_ASSERT('s', "7f", !test1->setChar(' ', sizeof(testC00)));
	TEST_ASSERT('s', "7g", test1->isEqualTo(testC00));
	if (test1) {
		test1->release();
	}
	res = res && checkSpace("(s)7", spaceCheck, 0);

	if (res) {
		verPrintf(("testString: All OSString Tests passed\n"));
	} else {
		logPrintf(("testString: Some OSString Tests failed\n"));
	}
}

void
testSymbol()
{
	bool res = true;
	int i, j;
	int countDups;
	const OSSymbol *cache[numStrCache];
	void *spaceCheck;

	// very first test initialises the OSMetaClass cache.
	cache[0] = IOSymbol::withCStringNoCopy(testC00);
	TEST_ASSERT('u', "0a", cache[0]);
	if (cache[0]) {
		cache[0]->release();
	}

	spaceCheck = checkPointSpace();

	// Setup the symbol cache, make sure it grows the symbol unique'ing
	// hash table.  Also determine that the symbol is created ok and that
	// it is indeed equal to the creating cString by strcmp.
	for (i = 0; i < numStrCache; i++) {
		cache[i] = OSSymbol::withCStringNoCopy(strCache[i]);
		if (!cache[i]) {
			verPrintf(("testSymbol(u) test 1a%d failed\n", i)); res = false;
		} else if (!cache[i]->isEqualTo(strCache[i])) {
			verPrintf(("testSymbol(u) test 1b%d failed\n", i)); res = false;
		}
	}

	// The strCache does have some duplicates in it, mostly 'the'.  Make
	// sure that we wind them and that different cache entries really are
	// different by strcmp.  Fundamental to OSSymbol semantics.
	countDups = 0;
	for (i = 0; i < numStrCache; i++) {
		for (j = i + 1; j < numStrCache; j++) {
			if (cache[i] != cache[j] && cache[i]->isEqualTo(cache[j])) {
				verPrintf(("testSymbol(u) test 2a%d,%d failed\n", i, j));
				res = false;
			} else if (cache[i] == cache[j]) {
				if (cache[i]->getRetainCount() == 1) {
					verPrintf(("testSymbol(u) test 2b%d,%d failed\n", i, j));
					res = false;
				}
				countDups++;
			}
		}
	}
	TEST_ASSERT('u', "2c", countDups);

	// Clear out the cache and check that the unique'ing hashtable has grown
	for (i = 0; i < numStrCache; i++) {
		if (cache[i]) {
			cache[i]->release();
			cache[i] = 0;
		}
	}
	// As of 1998-11-17 the hash growth is 364.
	res = res && checkSpace("(u)3", spaceCheck, 972);
	logSpace();

	// Check for leaks by repeating the cacheing and freeing
	spaceCheck = checkPointSpace();
	for (i = 0; i < numStrCache; i++) {
		cache[i] = OSSymbol::withCString(strCache[i]);
	}
	for (i = 0; i < numStrCache; i++) {
		if (cache[i]) {
			cache[i]->release();
			cache[i] = 0;
		}
	}
	res = res && checkSpace("(u)4", spaceCheck, 0);

	// Check that the OSString based symbol constructors work
	// and that they don't leak, and finally double check that while
	// the cache is active the symbol semantics still work.
	spaceCheck = checkPointSpace();
	for (i = 0; i < numStrCache; i++) {
		OSString *tmpStr;

		tmpStr = (i & 1)
		    ? OSString::withCString(strCache[i])
		    : OSString::withCStringNoCopy(strCache[i]);
		if (tmpStr) {
			cache[i] = OSSymbol::withString(tmpStr);
			if (!cache[i]) {
				verPrintf(("testSymbol(u) test 5a%d failed\n", i));
				res = false;
			}
			tmpStr->release();
		}
	}

	for (i = 0; i < numStrCache; i++) {
		if (cache[i]) {
			const OSSymbol *tmpSymb;

			tmpSymb = OSSymbol::withCStringNoCopy(strCache[i]);
			if (cache[i] != tmpSymb) {
				verPrintf(("testSymbol(u) test 5b%d failed\n", i));
				res = false;
			}
			tmpSymb->release();
			cache[i]->release();
			cache[i] = 0;
		} else {
			verPrintf(("testSymbol(u) test 5c%d failed\n", i));
			res = false;
		}
	}
	res = res && checkSpace("(u)5", spaceCheck, 0);

	if (res) {
		verPrintf(("testSymbol: All OSSymbol Tests passed\n"));
	} else {
		logPrintf(("testSymbol: Some OSSymbol Tests failed\n"));
	}
}

#endif /* DEBUG */
