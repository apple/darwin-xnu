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
#include <IOKit/pwr_mgt/IOPMPowerSourceList.h>
#include <IOKit/pwr_mgt/IOPMPowerSource.h>

#define super OSObject
OSDefineMetaClassAndStructors(IOPMPowerSourceList,OSObject)

//*********************************************************************************
// init
//
//*********************************************************************************
void IOPMPowerSourceList::initialize ( void )
{
    firstItem = NULL;
    length = 0;
}

//*********************************************************************************
// addToList
//
//*********************************************************************************

IOReturn IOPMPowerSourceList::addToList ( IOPMPowerSource * newPowerSource )
{
    IOPMPowerSource * nextPowerSource;
    nextPowerSource = firstItem;				// Is new object already in the list?
    while (  nextPowerSource != NULL ) {
        if ( nextPowerSource == newPowerSource ) {
            return IOPMNoErr;				// yes, just return
        }
        nextPowerSource = nextInList(nextPowerSource);
    }
    newPowerSource->nextInList = firstItem;		// add it to list
    firstItem = newPowerSource;
    length += 1;
    return IOPMNoErr;
}


//*********************************************************************************
// firstInList
//
//*********************************************************************************

IOPMPowerSource * IOPMPowerSourceList::firstInList ( void )
{
    return firstItem;
}

//*********************************************************************************
// nextInList
//
//*********************************************************************************

IOPMPowerSource * IOPMPowerSourceList::nextInList ( IOPMPowerSource * currentItem )
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

unsigned long IOPMPowerSourceList::numberOfItems ( void )
{
    return length;
}

//*********************************************************************************
// removeFromList
//
// Find the item in the list, unlink it, and free it.
//*********************************************************************************

IOReturn IOPMPowerSourceList::removeFromList ( IOPMPowerSource * theItem )
{
    IOPMPowerSource * item = firstItem;
    IOPMPowerSource * temp;

    if ( item != NULL ) {
        if ( item  == theItem ) {
            firstItem = item->nextInList;
            length--;
            item->release();
            return IOPMNoErr;
        }
        while ( item->nextInList != NULL ) {
            if ( item->nextInList == theItem ) {
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

void IOPMPowerSourceList::free (void )
{
    IOPMPowerSource * next = firstItem;

    while ( next != NULL ) {
        firstItem = next->nextInList;
        length--;
        next->release();
        next = firstItem;        
    }
super::free();
}







