/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
#include <IOKit/pwr_mgt/IOPM.h>
#include <IOKit/pwr_mgt/IOPMinformeeList.h>
#include <IOKit/pwr_mgt/IOPMinformee.h>

#define super OSObject
OSDefineMetaClassAndStructors(IOPMinformeeList,OSObject)

//*********************************************************************************
// init
//
//*********************************************************************************
void IOPMinformeeList::initialize ( void )
{
    firstItem = NULL;
    length = 0;
}

//*********************************************************************************
// addToList
//
//*********************************************************************************

IOReturn IOPMinformeeList::addToList ( IOPMinformee * newInformee )
{
    IOPMinformee * nextInformee;
    nextInformee = firstItem;				// Is new object already in the list?
    while (  nextInformee != NULL ) {
        if ( nextInformee->whatObject == newInformee->whatObject ) {
            return IOPMNoErr;				// yes, just return
        }
        nextInformee = nextInList(nextInformee);
    }
    newInformee->nextInList = firstItem;		// add it to list
    firstItem = newInformee;
    length += 1;
    return IOPMNoErr;
}


//*********************************************************************************
// firstInList
//
//*********************************************************************************

IOPMinformee * IOPMinformeeList::firstInList ( void )
{
    return firstItem;
}

//*********************************************************************************
// nextInList
//
//*********************************************************************************

IOPMinformee * IOPMinformeeList::nextInList ( IOPMinformee * currentItem )
{
    if ( currentItem != NULL ) {
       return (currentItem->nextInList);
    }
    return NULL;
}

//*********************************************************************************
// numberOfItems
//
//*********************************************************************************

unsigned long IOPMinformeeList::numberOfItems ( void )
{
    return length;
}

//*********************************************************************************
// findItem
//
// Look through the list for the one which points to the object identified
// by the parameter.  Return a pointer to the list item or NULL.
//*********************************************************************************

IOPMinformee * IOPMinformeeList::findItem ( IOService * driverOrChild )
{
    IOPMinformee * nextObject;

    nextObject = firstInList();
    while (  nextObject != NULL ) {
        if ( nextObject->whatObject == driverOrChild ) {
            return nextObject;
        }
        nextObject = nextInList(nextObject);
    }
    return NULL;
}


//*********************************************************************************
// removeFromList
//
// Find the item in the list, unlink it, and free it.
//*********************************************************************************

IOReturn IOPMinformeeList::removeFromList ( IOService * theItem )
{
    IOPMinformee * item = firstItem;
    IOPMinformee * temp;

    if ( item != NULL ) {
        if ( item->whatObject == theItem ) {
            firstItem = item->nextInList;
            length--;
            item->release();
            return IOPMNoErr;
        }
        while ( item->nextInList != NULL ) {
            if ( item->nextInList->whatObject == theItem ) {
                temp = item->nextInList;
                item->nextInList = temp->nextInList;
                length--;
                temp->release();
                return IOPMNoErr;
            }
            item = item->nextInList;
        }
    }
    return IOPMNoErr;
}


//*********************************************************************************
// free
//
// Free all items in the list, and then free the list itself
//*********************************************************************************

void IOPMinformeeList::free (void )
{
    IOPMinformee * next = firstItem;

    while ( next != NULL ) {
        firstItem = next->nextInList;
        length--;
        next->release();
        next = firstItem;        
    }
super::free();
}

