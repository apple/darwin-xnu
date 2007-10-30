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

//******************************************************************************
// getSharedRecursiveLock
//
//******************************************************************************
IORecursiveLock *IOPMinformeeList::getSharedRecursiveLock( void )
{
    static IORecursiveLock *sharedListLock = NULL;
    
    /* A running system could have 50-60+ instances of IOPMInformeeList. 
     * They'll share this lock, since list insertion and removal is relatively
     * rare, and generally tied to major events like device discovery.
     *
     * getSharedRecursiveLock() is called from IOStartIOKit to initialize
     * the sharedListLock before any IOPMinformeeLists are instantiated.
     *
     * The IOPMinformeeList class will be around for the lifetime of the system,
     * we don't worry about freeing this lock.
     */

    if ( NULL == sharedListLock )
    {
        sharedListLock = IORecursiveLockAlloc();
    }
    return sharedListLock;
}

 //*********************************************************************************
// appendNewInformee
 //
 //*********************************************************************************
IOPMinformee *IOPMinformeeList::appendNewInformee ( IOService * newObject )
{
    IOPMinformee * newInformee;
    
    if (!newObject)
        return NULL;
 
    newInformee = IOPMinformee::withObject (newObject);    

    if (!newInformee)
        return NULL;

    if( IOPMNoErr == addToList (newInformee))
        return newInformee;
    else
        return NULL;
}


//*********************************************************************************
// addToList
// *OBSOLETE* do not call from outside of this file.
// Try appendNewInformee() instead
//*********************************************************************************
IOReturn IOPMinformeeList::addToList ( IOPMinformee * newInformee )
{
    IOPMinformee * nextInformee;
    IORecursiveLock    *listLock = getSharedRecursiveLock();

    if(!listLock)
        return kIOReturnError;

    IORecursiveLockLock(listLock);
    nextInformee = firstItem;				
    
    // Is new object already in the list?
    while (  nextInformee != NULL ) 
    {
        if ( nextInformee->whatObject == newInformee->whatObject ) 
        {
            // object is present; just exit
            goto unlock_and_exit;
        }
        nextInformee = nextInList(nextInformee);
    }

    // add it to the front of the list
    newInformee->nextInList = firstItem;
    firstItem = newInformee;
    length++;

unlock_and_exit:
    IORecursiveLockUnlock(listLock);
    return IOPMNoErr;
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
    IORecursiveLock    *listLock = getSharedRecursiveLock();

    if ( NULL == item ) 
        return IOPMNoErr;
    if(!listLock) 
        return kIOReturnError;

    IORecursiveLockLock( listLock );
    
    if ( item->whatObject == theItem ) 
    {
        firstItem = item->nextInList;
        length--;
        item->release();
        goto unlock_and_exit;
    }
    
    while ( item->nextInList != NULL ) 
    {
        if ( item->nextInList->whatObject == theItem ) 
        {
            temp = item->nextInList;
            item->nextInList = temp->nextInList;
            length--;
            temp->release();
            goto unlock_and_exit;
        }
        item = item->nextInList;
    }

unlock_and_exit:
    IORecursiveLockUnlock(listLock);
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

