/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
#if DEBUG
#include "Tests.h"

#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSSet.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSString.h>
#include <libkern/c++/OSSymbol.h>
#include <libkern/c++/OSCollectionIterator.h>

void testArray()
{
    bool res = true;
    void *spaceCheck, *spaceCheck2 , *spaceCheck3;
    int i, j, count, count2;
    OSObject *cache[numStrCache], *str, *sym;
    OSArray *array1, *array2;

    // Do first test without memory leak tests to initialise the metaclass
    array1 = OSArray::withCapacity(1);
    TEST_ASSERT('A', "0a", array1);
    if (array1)
        array1->release();

    // Grow the symbol pool to maximum
    for (i = 0; i < numStrCache; i++)
        cache[i] = (OSObject *) OSSymbol::withCStringNoCopy(strCache[i]);
    for (i = 0; i < numStrCache; i++)
        cache[i]->release();

    // Create and destroy an array
    spaceCheck = checkPointSpace();
    array1 = OSArray::withCapacity(1);
    TEST_ASSERT('A', "1a", array1);
    if (array1) {
        TEST_ASSERT('A', "1b", !array1->getCount());
        TEST_ASSERT('A', "1c", 1 == array1->getCapacity());
        TEST_ASSERT('A', "1d", 1 == array1->getCapacityIncrement());
        TEST_ASSERT('A', "1e", 4 == array1->setCapacityIncrement(4));
        TEST_ASSERT('A', "1f", 4 == array1->getCapacityIncrement());
        TEST_ASSERT('A', "1g", 8 == array1->ensureCapacity(5));

        spaceCheck2 = checkPointSpace();
        cache[0] = IOString::withCStringNoCopy(strCache[0]);

        spaceCheck3 = checkPointSpace();
        TEST_ASSERT('A', "1h", array1->setObject(cache[0]));
        TEST_ASSERT('A', "1i", cache[0] == array1->getObject(0));
        cache[0]->release();
        res = res && checkSpace("(A)1j", spaceCheck3, 0);

        TEST_ASSERT('A', "1k", 1 == array1->getCount());
        array1->flushCollection();
        TEST_ASSERT('A', "1l", !array1->getCount());
        res = res && checkSpace("(A)1m", spaceCheck2, 0);

        array1->release();
    }
    res = res && checkSpace("(A)1", spaceCheck, 0);

    // Check the creation of a sizable OSArray from an array of IOObjects
    // Also check indexing into the array.
    spaceCheck = checkPointSpace();
    for (i = 0; i < numStrCache; i++)
        cache[i] = OSString::withCStringNoCopy(strCache[i]);
    array1 = OSArray::withObjects(cache, numStrCache, numStrCache);
    TEST_ASSERT('A', "2a", array1);
    for (i = 0; i < numStrCache; i++)
        cache[i]->release();
    if (array1) {
        TEST_ASSERT('A', "2b", numStrCache == (int) array1->getCount());
        TEST_ASSERT('A', "2c", numStrCache == (int) array1->getCapacity());
        TEST_ASSERT('A', "2d",
                    numStrCache == (int) array1->getCapacityIncrement());

        for (i = 0; (str = array1->getObject(i)); i++) {
            if (str != cache[i]) {
                verPrintf(("testArray(A) test 2e%d failed\n", i));
                res = false;
            }
        }
        TEST_ASSERT('A', "2f", numStrCache == i);
        array1->release();
    }
    res = res && checkSpace("(A)2", spaceCheck, 0);

    // Test array creation from another array by both the setObject method
    // and the withArray factory.  And test __takeObject code first
    // with tail removal then with head removal
    spaceCheck = checkPointSpace();
    for (i = 0; i < numStrCache; i++)
        cache[i] = OSString::withCStringNoCopy(strCache[i]);
    array1 = OSArray::withObjects(cache, numStrCache, numStrCache);
    TEST_ASSERT('A', "3a", array1);
    for (i = 0; i < numStrCache; i++)
        cache[i]->release();
    array2 = 0;
    if (array1) {
        array2 = OSArray::withCapacity(1);
        TEST_ASSERT('A', "3b", array2);
        TEST_ASSERT('A', "3c", !array2->getCount());
        TEST_ASSERT('A', "3d", array2->setObject(array1));
        TEST_ASSERT('A', "3e", array1->getCount() == array2->getCount());
    }
    if (array2) {
        count = 0;
        TEST_ASSERT('A', "3f", numStrCache == (int) array2->getCount());
        for (i = array2->getCount(); (str = array2->__takeObject(--i)); ) {
            if (str != cache[i]) {
                verPrintf(("testArray(A) test 3g%d failed\n", i));
                res = false;
            }
            count += ((int) array2->getCount() == i);
            str->release();
        }
        TEST_ASSERT('A', "3h", count == numStrCache);
        TEST_ASSERT('A', "3i", -1 == i);
        TEST_ASSERT('A', "3j", !array2->getCount());

        spaceCheck2 = checkPointSpace();
        array2->flushCollection();
        res = res && checkSpace("(A)3k", spaceCheck2, 0);

        array2->release();
        array2 = 0;
    }
    if (array1) {
        array2 = OSArray::withArray(array1, numStrCache - 1);
        TEST_ASSERT('A', "3l", !array2);
        array2 = OSArray::withArray(array1, array1->getCount());
        TEST_ASSERT('A', "3m", array2);
        array1->release();
    }
    if (array2) {
        count = 0;
        TEST_ASSERT('A', "3o", numStrCache == (int) array2->getCount());
        for (i = 0; (str = array2->__takeObject(0)); i++) {
            count += (str == cache[i]);
            str->release();
        }
        TEST_ASSERT('A', "3p", count == numStrCache);
        TEST_ASSERT('A', "3q", !array2->getCount());
        array2->release();
        array2 = 0;
    }
    res = res && checkSpace("(A)3", spaceCheck, 0);

    // Test object replacement from one array to another
    spaceCheck = checkPointSpace();
    array1 = OSArray::withCapacity(numStrCache);
    TEST_ASSERT('A', "4a", array1);
    if (array1) {
        count = count2 = 0;
        for (i = 0; i < numStrCache; i++) {
            str = OSString::withCStringNoCopy(strCache[i]);
            count += array1->setObject(str);
            count2 += (str == array1->lastObject());
            str->release();
        }
        TEST_ASSERT('A', "4b", numStrCache == (int) array1->getCount());
        TEST_ASSERT('A', "4c", count == numStrCache);
        TEST_ASSERT('A', "4d", count2 == numStrCache);
    }
    array2 = OSArray::withCapacity(1);
    TEST_ASSERT('A', "4e", array2);
    if (array2) {
        count = count2 = 0;
        str = (OSObject *) OSSymbol::withCStringNoCopy(strCache[0]);
        for (i = 0; i < numStrCache; i++) {
            sym = (OSObject *) OSSymbol::withCStringNoCopy(strCache[i]);
            count += array2->setObject(sym, 0);
            count2 += (str == array2->lastObject());
            sym->release();
        }
        str->release();
        TEST_ASSERT('A', "4f", numStrCache == (int) array2->getCount());
        TEST_ASSERT('A', "4g", count == numStrCache);
        TEST_ASSERT('A', "4h", count2 == numStrCache);
    }
    if (array1 && array2) {

        count = count2 = 0;
        for (i = array1->getCount() - 1; (sym = array2->__takeObject(0)); i--) {
            str = array1->replaceObject(sym, i);
            count  += (str != 0);
            count2 += (sym != str);
            if (str)
                str->release();
            if (sym)
                sym->release();
        }
        TEST_ASSERT('A', "4k", numStrCache == (int) array1->getCount());
        TEST_ASSERT('A', "4l", count == numStrCache);
        TEST_ASSERT('A', "4m", count2 == numStrCache);
        array1->release();
        array2->release();
    }
    else {
        if (array1) array1->release();
        if (array2) array2->release();
    }
    res = res && checkSpace("(A)4", spaceCheck, 0);

    // Test array duplicate removal
    spaceCheck = checkPointSpace();
    array1 = OSArray::withCapacity(numStrCache);
    TEST_ASSERT('A', "5a", array1);
    if (array1) {
        for (i = 0; i < numStrCache; i++) {
            sym = (OSObject *) OSSymbol::withCStringNoCopy(strCache[i]);
            count += array1->setObject(sym);
            sym->release();
        }
        TEST_ASSERT('A', "5b", numStrCache == (int) array1->getCount());

        // remove duplicates
        for (i = 0; (sym = array1->getObject(i)); )
            if (sym->getRetainCount() == 1)
                i++;
            else {
                //sym = array1->__takeObject(i);
                //sym->release();
                array1->removeObject(i);
            }
        TEST_ASSERT('A', "5c", numStrCache != (int) array1->getCount());

        // check to see that all symbols are really there
        for (count = 0, i = 0; i < numStrCache; i++) {
            sym = (OSObject *) OSSymbol::withCStringNoCopy(strCache[i]);
            for (count2 = false, j = 0; (str = array1->getObject(j)); j++)
                if (str == sym) {
                    count2 = true;
                    break;
                }
            count += count2;
            sym->release();
        }
        TEST_ASSERT('A', "5c", count == numStrCache);
        array1->release();
    }
    res = res && checkSpace("(S)5", spaceCheck, 0);

    if (res)
        verPrintf(("testArray: All OSArray Tests passed\n"));
    else
        logPrintf(("testArray: Some OSArray Tests failed\n"));
}

void testSet()
{
    bool res = true;
    void *spaceCheck, *spaceCheck2 , *spaceCheck3;
    int i, count, count2;
    OSObject *cache[numStrCache], *str, *sym;
    OSSet *set1, *set2;
    OSArray *array;

    // Do first test without memory leak tests to initialise the metaclass
    set1 = OSSet::withCapacity(1);
    TEST_ASSERT('S', "0a", set1);
    if (set1)
        set1->release();

    // Grow the symbol pool to maximum
    for (i = 0; i < numStrCache; i++)
        cache[i] = (OSObject *) OSSymbol::withCStringNoCopy(strCache[i]);
    for (i = 0; i < numStrCache; i++)
        cache[i]->release();

    // Create and destroy an set
    spaceCheck = checkPointSpace();
    set1 = OSSet::withCapacity(1);
    TEST_ASSERT('S', "1a", set1);
    if (set1) {
        TEST_ASSERT('S', "1b", !set1->getCount());
        TEST_ASSERT('S', "1c", 1 == set1->getCapacity());
        TEST_ASSERT('S', "1d", 1 == set1->getCapacityIncrement());
        TEST_ASSERT('S', "1e", 4 == set1->setCapacityIncrement(4));
        TEST_ASSERT('S', "1f", 4 == set1->getCapacityIncrement());
        TEST_ASSERT('S', "1g", 8 == set1->ensureCapacity(5));

        spaceCheck2 = checkPointSpace();
        cache[0] = IOString::withCStringNoCopy(strCache[0]);

        spaceCheck3 = checkPointSpace();
        TEST_ASSERT('S', "1h", set1->setObject(cache[0]));
        TEST_ASSERT('S', "1i", set1->containsObject(cache[0]));
        TEST_ASSERT('S', "1j", cache[0] == set1->getAnyObject());
        cache[0]->release();
        res = res && checkSpace("(S)1k", spaceCheck3, 0);

        TEST_ASSERT('S', "1l", 1 == set1->getCount());
        set1->flushCollection();
        TEST_ASSERT('S', "1m", !set1->getCount());
        res = res && checkSpace("(S)1n", spaceCheck2, 0);

        set1->release();
    }
    res = res && checkSpace("(S)1", spaceCheck, 0);

    // Check the creation of a sizable OSSet from an set of IOObjects
    // Also check member test of set.
    spaceCheck = checkPointSpace();
    for (i = 0; i < numStrCache; i++)
        cache[i] = OSString::withCStringNoCopy(strCache[i]);
    set1 = OSSet::withObjects(cache, numStrCache, numStrCache);
    TEST_ASSERT('S', "2a", set1);
    for (i = 0; i < numStrCache; i++)
        cache[i]->release();
    if (set1) {
        TEST_ASSERT('S', "2b", numStrCache == (int) set1->getCount());
        TEST_ASSERT('S', "2c", numStrCache == (int) set1->getCapacity());
        TEST_ASSERT('S', "2d",
                    numStrCache == (int) set1->getCapacityIncrement());

        count = 0;
        for (i = set1->getCount(); --i >= 0; )
            count += set1->member(cache[i]);

        TEST_ASSERT('S', "2e", numStrCache == count);
        set1->release();
    }
    res = res && checkSpace("(S)2", spaceCheck, 0);

    // Test set creation from another set by both the setObject method
    // and the withArray factory.  And test __takeObject code first
    // with tail removal then with head removal
    spaceCheck = checkPointSpace();
    for (i = 0; i < numStrCache; i++)
        cache[i] = OSString::withCStringNoCopy(strCache[i]);
    set1 = OSSet::withObjects(cache, numStrCache, numStrCache);
    TEST_ASSERT('S', "3a", set1);
    for (i = 0; i < numStrCache; i++)
        cache[i]->release();
    set2 = 0;
    if (set1) {
        set2 = OSSet::withCapacity(set1->getCount());
        TEST_ASSERT('S', "3b", set2);
        TEST_ASSERT('S', "3c", !set2->getCount());
        TEST_ASSERT('S', "3d", set2->setObject(set1));
        TEST_ASSERT('S', "3e", set1->getCount() == set2->getCount());
    }
    if (set2) {
        TEST_ASSERT('S', "3f", numStrCache == (int) set2->getCount());
        count = count2 = 0;
        while ( (str = set2->getAnyObject()) ) {
            count  += set2->__takeObject(str);
            count2 += set1->member(str);
            str->release();
        }
        TEST_ASSERT('S', "3g", !set2->getCount());
        TEST_ASSERT('S', "3h", numStrCache == count);
        TEST_ASSERT('S', "3i", numStrCache == count2);

        spaceCheck2 = checkPointSpace();
        set2->flushCollection();
        res = res && checkSpace("(S)3j", spaceCheck2, 0);

        set2->release();
        set2 = 0;
    }
    if (set1) {
        set2 = OSSet::withSet(set1, numStrCache - 1);
        TEST_ASSERT('S', "3k", !set2);
        set2 = OSSet::withSet(set1, set1->getCount());
        TEST_ASSERT('S', "3l", set2);
        set1->release();
    }
    if (set2) {
        TEST_ASSERT('S', "3m", numStrCache == (int) set2->getCount());
        i = count = count2 = 0;
        while ( (str = set2->getAnyObject()) ) {
            count  += set2->__takeObject(str);
            count2 += (cache[i++] == str);
            str->release();
        }
        TEST_ASSERT('S', "3n", !set2->getCount());
        TEST_ASSERT('S', "3o", numStrCache == count);
        TEST_ASSERT('S', "3p", numStrCache == count2);

        set2->release();
        set2 = 0;
    }
    res = res && checkSpace("(S)3", spaceCheck, 0);

    // Test duplicate removal
    spaceCheck = checkPointSpace();
    set2 = 0;
    set1 = OSSet::withCapacity(numStrCache);
    TEST_ASSERT('S', "4a", set1);
    if (set1) {
        count = 0;
        for (i = 0; i < numStrCache; i++) {
            sym = (OSObject *) OSSymbol::withCStringNoCopy(strCache[i]);
            count += set1->setObject(sym);
            sym->release();
        }
        TEST_ASSERT('S', "4b", numStrCache != (int) set1->getCount());
        TEST_ASSERT('S', "4c", count == (int) set1->getCount());

        count = count2 = 0;
        for (i = 0; i < numStrCache; i++) {
            sym = (OSObject *) OSSymbol::withCStringNoCopy(strCache[i]);
            count += set1->member(sym);
            count2 += sym->getRetainCount();
            sym->release();
        }
        TEST_ASSERT('S', "4d", count  == numStrCache);
        TEST_ASSERT('S', "4e", count2 == numStrCache * 2);

        set2 = OSSet::withSet(set1, 2 * set1->getCount());
    }
    TEST_ASSERT('S', "4f", set2);
    if (set2) {
        set2->setObject(set1);
        TEST_ASSERT('S', "4g", set1->getCount() == set2->getCount());
        set1->release();
        set2->release();
    }
    res = res && checkSpace("(S)4", spaceCheck, 0);

    // Test array duplicate removal
    spaceCheck = checkPointSpace();
    array = OSArray::withCapacity(numStrCache);
    for (i = 0; i < numStrCache; i++) {
        sym = (OSObject *) OSSymbol::withCStringNoCopy(strCache[i]);
        count += array->setObject(sym);
        sym->release();
    }
    set1 = OSSet::withArray(array, numStrCache);
    TEST_ASSERT('S', "5a", set1);
    if (set1) {
        TEST_ASSERT('S', "5b", array->getCount() != set1->getCount());
        array->release();

        count = count2 = set1->getCount();
        while ( (sym = set1->getAnyObject()) ) {
            count  -= set1->__takeObject(sym);
            count2 -= sym->getRetainCount();
            sym->release();
        }
        TEST_ASSERT('S', "5c", !count);
        TEST_ASSERT('S', "5d", !count2);
        set1->release();
    }
    res = res && checkSpace("(S)5", spaceCheck, 0);

    if (res)
        verPrintf(("testSet: All OSSet Tests passed\n"));
    else
        logPrintf(("testSet: Some OSSet Tests failed\n"));
}

void testDictionary()
{
    bool res = true;
    void *spaceCheck, *spaceCheck2, *spaceCheck3;
    OSObject *cache[numStrCache];
    OSString *str;
    const OSSymbol *symCache[numStrCache], *sym;
    OSDictionary *dict1, *dict2;
    int i, numSymbols, count1, count2;

    // Do first test without memory leak tests to initialise the metaclass
    dict1 = OSDictionary::withCapacity(1);
    TEST_ASSERT('D', "0a", dict1);
    if (dict1)
        dict1->release();

    // Grow the symbol pool to maximum
    for (i = 0; i < numStrCache; i++)
        symCache[i] = OSSymbol::withCStringNoCopy(strCache[i]);
    for (i = 0; i < numStrCache; i++)
        symCache[i]->release();

    // Create and destroy a dictionary
    spaceCheck = checkPointSpace();
    dict1 = OSDictionary::withCapacity(1);
    TEST_ASSERT('D', "1a", dict1);
    if (dict1) {
        TEST_ASSERT('D', "1b", !dict1->getCount());
        TEST_ASSERT('D', "1c", 1 == dict1->getCapacity());
        TEST_ASSERT('D', "1d", 1 == dict1->getCapacityIncrement());
        TEST_ASSERT('D', "1e", 4 == dict1->setCapacityIncrement(4));
        TEST_ASSERT('D', "1f", 4 == dict1->getCapacityIncrement());
        TEST_ASSERT('D', "1g", 8 == dict1->ensureCapacity(5));

        spaceCheck2 = checkPointSpace();
        sym = OSSymbol::withCStringNoCopy(strCache[0]);

        spaceCheck3 = checkPointSpace();
        TEST_ASSERT('D', "1h", dict1->setObject((OSObject *) sym, sym));
        TEST_ASSERT('D', "1i", (OSObject *) sym == dict1->getObject(sym));
        sym->release();
        TEST_ASSERT('D', "1i", 2 == sym->getRetainCount());
        res = res && checkSpace("(D)1j", spaceCheck3, 0);

        TEST_ASSERT('D', "1k", 1 == dict1->getCount());
        dict1->flushCollection();
        TEST_ASSERT('D', "1l", !dict1->getCount());
        res = res && checkSpace("(D)1m", spaceCheck2, 0);

        dict1->release();
    }
    res = res && checkSpace("(D)1", spaceCheck, 0);

    // Check the creation of a sizable OSDictionary from an array of IOObjects
    // Also check indexing into the array.
    spaceCheck = checkPointSpace();
    for (i = 0, numSymbols = 0; i < numStrCache; i++) {
        sym = OSSymbol::withCStringNoCopy(strCache[i]);
        if (1 == sym->getRetainCount())
            symCache[numSymbols++] = sym;
        else
            sym->release();
    }
    dict1 = OSDictionary::withObjects(
                    (OSObject **) symCache, symCache, numSymbols, numSymbols);
    TEST_ASSERT('D', "2a", dict1);
    count1 = count2 = 0;
    for (i = 0; i < numSymbols; i++)
        count1 += (symCache[i]->getRetainCount() == 3);
    TEST_ASSERT('D', "2b", count1 == numSymbols);
    if (dict1) {
        TEST_ASSERT('D', "2c", numSymbols == (int) dict1->getCount());
        TEST_ASSERT('D', "2d", numSymbols == (int) dict1->getCapacity());
        TEST_ASSERT('D', "2e",
                    numSymbols == (int) dict1->getCapacityIncrement());

        for (i = dict1->getCount(); --i >= 0; ) {
            str = (OSString *) dict1->getObject(symCache[i]);
            if (str != (OSString *) symCache[i]) {
                verPrintf(("testDictionary(D) test 2f%d failed\n", i));
                res = false;
            }
        }
        dict1->release();
    }
    count1 = count2 = 0;
    for (i = 0; i < numSymbols; i++) {
        count1 += (symCache[i]->getRetainCount() == 1);
        symCache[i]->release();
    }
    TEST_ASSERT('D', "2g", count1 == numSymbols);
    res = res && checkSpace("(D)2", spaceCheck, 0);

    // Check the creation of a sizable Dictionary from an array of IOStrings
    // Also check searching dictionary use OSString for a key.
    spaceCheck = checkPointSpace();
    for (i = 0, numSymbols = 0; i < numStrCache; i++) {
        sym = OSSymbol::withCStringNoCopy(strCache[i]);
        if (1 == sym->getRetainCount()) {
            cache[numSymbols] = OSString::withCStringNoCopy(strCache[i]);
            symCache[numSymbols] = sym;
            numSymbols++;
        }
        else
            sym->release();
    }
    dict1 = OSDictionary::withObjects((OSObject **) symCache,
                                      (OSString **) cache,
                                      numSymbols, numSymbols);
    TEST_ASSERT('D', "3a", dict1);
    count1 = count2 = 0;
    for (i = 0; i < numSymbols; i++) {
        count1 += (symCache[i]->getRetainCount() == 3);
        count2 += (cache[i]->getRetainCount() == 1);
    }
    TEST_ASSERT('D', "3b", count1 == numSymbols);
    TEST_ASSERT('D', "3c", count2 == numSymbols);
    if (dict1) {
        count1 = count2 = 0;
        for (i = 0; i < numSymbols; i++) {
            str = (OSString *) cache[i];
            count1 += (symCache[i] == (const OSSymbol *) dict1->getObject(str));
            count2 += (symCache[i]->getRetainCount() == 3);
        }
        TEST_ASSERT('D', "3d", count1 == numSymbols);
        TEST_ASSERT('D', "3e", count2 == numSymbols);

        count1 = count2 = 0;
        for (i = 0; i < numSymbols; i++) {
            const char *cStr = ((OSString *) cache[i])->getCStringNoCopy();

            count1 += (symCache[i] == (const OSSymbol *) dict1->getObject(cStr));
            count2 += (symCache[i]->getRetainCount() == 3);
        }
        TEST_ASSERT('D', "3f", count1 == numSymbols);
        TEST_ASSERT('D', "3g", count2 == numSymbols);

        dict1->release();
    }
    count1 = count2 = 0;
    for (i = 0; i < numSymbols; i++) {
        count1 += (symCache[i]->getRetainCount() == 1);
        count2 += (cache[i]->getRetainCount() == 1);
        symCache[i]->release();
        cache[i]->release();
    }
    TEST_ASSERT('D', "3h", count1 == numSymbols);
    res = res && checkSpace("(D)3", spaceCheck, 0);

    // Check the creation of a small dictionary then grow it one item at a time
    // Create a new dictionary from the old dictionary.
    // Finally remove each item permanently.
    spaceCheck = checkPointSpace();
    for (i = 0, numSymbols = 0; i < numStrCache; i++) {
        sym = OSSymbol::withCStringNoCopy(strCache[i]);
        if (1 == sym->getRetainCount()) {
            cache[numSymbols] = OSString::withCStringNoCopy(strCache[i]);
            symCache[numSymbols] = sym;
            numSymbols++;
        }
        else
            sym->release();
    }
    dict2 = 0;
    dict1 = OSDictionary::withCapacity(1);
    TEST_ASSERT('D', "4a", dict1);
    if (dict1) {
        count1 = count2 = 0;
        for (i = 0; i < numSymbols; i++) {
            sym = symCache[i];
            count1 += ((OSObject *) sym == dict1->setObject((OSObject *) sym,
                                               sym->getCStringNoCopy()));
            count2 += (sym->getRetainCount() == 3);
        }
        TEST_ASSERT('D', "4b", numSymbols == (int) dict1->getCount());
        TEST_ASSERT('D', "4c", numSymbols == count1);
        TEST_ASSERT('D', "4d", numSymbols == count2);

        dict2 = OSDictionary::withDictionary(dict1, numSymbols-1);
        TEST_ASSERT('D', "4b", !dict2);
        dict2 = OSDictionary::withDictionary(dict1, numSymbols);
    }
    TEST_ASSERT('D', "4e", dict2);
    if (dict2) {
        dict1->release(); dict1 = 0;

        TEST_ASSERT('D', "4f", numSymbols == (int) dict2->getCount());

        count1 = count2 = 0;
        for (i = 0; i < numSymbols; i++) {
            OSObject *replacedObject;

            sym = symCache[i];
            str = (OSString *) cache[i];
            replacedObject = dict2->setObject(str, str);
            count1 += ((OSString *) sym == replacedObject);
            replacedObject->release();
            count2 += (sym->getRetainCount() == 2);
            str->release();
        }
        TEST_ASSERT('D', "4g", numSymbols == count1);
        TEST_ASSERT('D', "4h", numSymbols == count2);

        count1 = count2 = 0;
        for (i = 0; i < numSymbols; i++) {
            sym = symCache[i];
            str = (OSString *) cache[i];
            count1 += (str == dict2->__takeObject(sym));
            str->release();
            count2 += (sym->getRetainCount() == 1);
            sym->release();
        }
        TEST_ASSERT('D', "4i", numSymbols == count1);
        TEST_ASSERT('D', "4j", numSymbols == count2);
        TEST_ASSERT('D', "4k", !dict2->getCount());
        dict2->release(); dict2 = 0;
    }
    else if (dict1)
        dict1->release();
    res = res && checkSpace("(D)4", spaceCheck, 0);

    if (res)
        verPrintf(("testDictionary: All OSDictionary Tests passed\n"));
    else
        logPrintf(("testDictionary: Some OSDictionary Tests failed\n"));
}

void testIterator()
{
    bool res = true;
    void *spaceCheck;
    OSObject *cache[numStrCache];
    OSString *str = 0;
    const OSSymbol *symCache[numStrCache], *sym;
    OSDictionary *dict;
    OSSet *set;
    OSArray *array, *bigReturn;
    OSCollectionIterator *iter1, *iter2;
    int i, numSymbols, count1, count2, count3;

    // Setup symbol and string pools
    for (i = 0, numSymbols = 0; i < numStrCache; i++) {
        sym = OSSymbol::withCStringNoCopy(strCache[i]);
        if (1 == sym->getRetainCount()) {
            cache[numSymbols] = OSString::withCStringNoCopy(strCache[i]);
            symCache[numSymbols] = sym;
            numSymbols++;
        }
        else
            sym->release();
    }

    // Test the array iterator
    spaceCheck = checkPointSpace();
    iter1 = iter2 = 0;
    array = OSArray::withCapacity(numSymbols);
    TEST_ASSERT('I', "1a", array);
    if (array) {
        count1 = count2 = 0;
        for (i = numSymbols; --i >= 0; )
            count1 += array->setObject(cache[i], 0);
        TEST_ASSERT('I', "1b", count1 == numSymbols);

        iter1 = OSCollectionIterator::withCollection(array);
        iter2 = OSCollectionIterator::withCollection(array);
    }
    TEST_ASSERT('I', "1c", iter1);
    TEST_ASSERT('I', "1d", iter2);
    if (iter1 && iter2) {
        count1 = count2 = count3 = 0;
        for (i = 0; (str = (IOString *) iter1->getNextObject()); i++) {
            bigReturn = iter2->nextEntries();
            count1 += (bigReturn->getCount() == 1);
            count2 += (cache[i] == bigReturn->getObject(0));
            count3 += (cache[i] == str);
        }
        TEST_ASSERT('I', "1e", count1 == numSymbols);
        TEST_ASSERT('I', "1f", count2 == numSymbols);
        TEST_ASSERT('I', "1g", count3 == numSymbols);
        TEST_ASSERT('I', "1h", iter1->valid());
        TEST_ASSERT('I', "1i", iter2->valid());

        iter1->reset();
        str = (OSString *) array->__takeObject(0);
        array->setObject(str, 0);
        str->release();
        TEST_ASSERT('I', "1j", !iter1->getNextObject());
        TEST_ASSERT('I', "1k", !iter1->valid());

        iter1->reset();
        count1 = count2 = count3 = 0;
        for (i = 0; ; i++) {
            if (i & 1)
                str = (OSString *) iter1->getNextObject();
            else if ( (bigReturn = iter1->nextEntries()) )
                str = (OSString *) bigReturn->getObject(0);
            else
                str = 0;

            if (!str)
                break;
            count1 += (cache[i] == str);
        }
        TEST_ASSERT('I', "1l", count1 == numSymbols);
        TEST_ASSERT('I', "1m", i == numSymbols);
        TEST_ASSERT('I', "1n", iter1->valid());

        TEST_ASSERT('I', "1o", 3 == array->getRetainCount());
        array->release();
    }

    if (iter1) iter1->release();
    if (iter2) iter2->release();
    res = res && checkSpace("(I)1", spaceCheck, 0);

    // Test the set iterator
    spaceCheck = checkPointSpace();
    iter1 = 0;
    set = OSSet::withCapacity(numSymbols);
    TEST_ASSERT('I', "2a", set);
    if (set) {
        count1 = count2 = 0;
        for (i = 0; i < numSymbols; i++)
            count1 += set->setObject(cache[i]);
        TEST_ASSERT('I', "2b", count1 == numSymbols);

        iter1 = OSCollectionIterator::withCollection(set);
        iter2 = OSCollectionIterator::withCollection(set);
    }
    TEST_ASSERT('I', "2c", iter1);
    TEST_ASSERT('I', "2d", iter2);
    if (iter1 && iter2) {
        count1 = count2 = count3 = 0;
        for (i = 0; (str = (IOString *) iter1->getNextObject()); i++) {
            bigReturn = iter2->nextEntries();
            count1 += (bigReturn->getCount() == 1);
            count2 += (cache[i] == bigReturn->getObject(0));
            count3 += (cache[i] == str);
        }
        TEST_ASSERT('I', "2e", count1 == numSymbols);
        TEST_ASSERT('I', "2f", count2 == numSymbols);
        TEST_ASSERT('I', "2g", count3 == numSymbols);
        TEST_ASSERT('I', "2h", iter1->valid());
        TEST_ASSERT('I', "2i", iter2->valid());

        iter1->reset();
        count1 = count2 = count3 = 0;
        for (i = 0; ; i++) {
            if (i & 1)
                str = (OSString *) iter1->getNextObject();
            else if ( (bigReturn = iter1->nextEntries()) )
                str = (OSString *) bigReturn->getObject(0);
            else
                str = 0;

            if (!str)
                break;
            count1 += (cache[i] == str);
        }
        TEST_ASSERT('I', "2l", count1 == numSymbols);
        TEST_ASSERT('I', "2m", i == numSymbols);
        TEST_ASSERT('I', "2n", iter1->valid());

        iter1->reset();
        str = (OSString *) set->getAnyObject();
        (void) set->__takeObject(str);
        set->setObject(str);
        str->release();
        TEST_ASSERT('I', "2j", !iter1->getNextObject());
        TEST_ASSERT('I', "2k", !iter1->valid());

        TEST_ASSERT('I', "2o", 3 == set->getRetainCount());
        set->release();
    }

    if (iter1) iter1->release();
    if (iter2) iter2->release();
    res = res && checkSpace("(I)2", spaceCheck, 0);

    // Test the dictionary iterator
    spaceCheck = checkPointSpace();
    iter1 = 0;
    dict = OSDictionary::withCapacity(numSymbols);
    TEST_ASSERT('I', "3a", dict);
    if (dict) {
        count1 = count2 = 0;
        for (i = 0; i < numSymbols; i++)
            count1 += (0 != dict->setObject(cache[i], symCache[i]));
        TEST_ASSERT('I', "3b", count1 == numSymbols);

        iter1 = OSCollectionIterator::withCollection(dict);
        iter2 = OSCollectionIterator::withCollection(dict);
    }
    TEST_ASSERT('I', "3c", iter1);
    TEST_ASSERT('I', "3d", iter2);
    if (iter1 && iter2) {
        count1 = count2 = count3 = 0;
        for (i = 0; (sym = (const IOSymbol *) iter1->getNextObject()); i++) {
            bigReturn = iter2->nextEntries();
            count1 += (bigReturn->getCount() == 2);
            count2 += (cache[i] == bigReturn->getObject(1));
            count3 += (symCache[i] == sym);
        }
        TEST_ASSERT('I', "3e", count1 == numSymbols);
        TEST_ASSERT('I', "3f", count2 == numSymbols);
        TEST_ASSERT('I', "3g", count3 == numSymbols);
        TEST_ASSERT('I', "3h", iter1->valid());
        TEST_ASSERT('I', "3i", iter2->valid());

        iter1->reset();
        count1 = count2 = count3 = 0;
        i = 0;
        for (i = 0; ; i++) {
            if (i & 1) {
                sym = (const OSSymbol *) iter1->getNextObject();
                str = 0;
            }
            else if ( (bigReturn = iter1->nextEntries()) ) {
                sym = (const OSSymbol *) bigReturn->getObject(0);
                str = (OSString *) bigReturn->getObject(1);
            }
            else
                sym = 0;

            if (!sym)
                break;

            count1 += (symCache[i] == sym);
            count2 += (!str || cache[i] == str);
        }
        TEST_ASSERT('I', "3l", count1 == numSymbols);
        TEST_ASSERT('I', "3m", count2 == numSymbols);
        TEST_ASSERT('I', "3n", i == numSymbols);
        TEST_ASSERT('I', "3o", iter1->valid());

        iter1->reset();
        str = (OSString *) dict->__takeObject(symCache[numSymbols-1]);
        dict->setObject(str, symCache[numSymbols-1]);
        str->release();
        TEST_ASSERT('I', "3j", !iter1->getNextObject());
        TEST_ASSERT('I', "3k", !iter1->valid());

        TEST_ASSERT('I', "3p", 3 == dict->getRetainCount());
        dict->release();
    }

    if (iter1) iter1->release();
    if (iter2) iter2->release();
    res = res && checkSpace("(I)3", spaceCheck, 0);

    count1 = count2 = count3 = 0;
    for (i = 0; i < numSymbols; i++) {
        count1 += (1 == cache[i]->getRetainCount());
        count2 += (1 == symCache[i]->getRetainCount());
        cache[i]->release();
        symCache[i]->release();
    }
    TEST_ASSERT('I', "4a", count1 == numSymbols);
    TEST_ASSERT('I', "4b", count2 == numSymbols);

    if (res)
        verPrintf(("testIterator: All OSCollectionIterator Tests passed\n"));
    else
        logPrintf(("testIterator: Some OSCollectionIterator Tests failed\n"));
}

#endif /* DEBUG */
