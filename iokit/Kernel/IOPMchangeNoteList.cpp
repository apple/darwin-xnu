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
#include <IOKit/pwr_mgt/IOPM.h>
#include <IOKit/pwr_mgt/IOPMchangeNoteList.h>

#define super OSObject
OSDefineMetaClassAndStructors(IOPMchangeNoteList,OSObject)

//*********************************************************************************
// init
//
//*********************************************************************************
void IOPMchangeNoteList::initialize ( void )
{
    long i;

    firstInList = 0;
    firstUnused = 0;
    for ( i = 0; i < IOPMMaxChangeNotes; i++ ) {
        changeNote[i].flags = IOPMNotInUse;
    }
}

//*********************************************************************************
// createChangeNote
//
//*********************************************************************************

long IOPMchangeNoteList::createChangeNote ( void )
{
    unsigned long i, j;

    i = increment(firstUnused);
    if ( firstInList == i ) {
        return -1;
    }
    j = firstUnused;
    firstUnused = i;

    return j;
}

//*********************************************************************************
// currentChange
//
// Return the ordinal of the first change note in the list.
// If the list is empty, return -1.
//*********************************************************************************

long IOPMchangeNoteList::currentChange ( void )
{
    if ( firstUnused == firstInList ) {
        return -1;
    }
    else {
        return firstInList;
    }
}

//*********************************************************************************
// latestChange
//
// Return the ordinal of the last change note in the list.
// If the list is empty, return -1.
//*********************************************************************************

long IOPMchangeNoteList::latestChange ( void )
{
    if ( firstUnused == firstInList ) {
        return -1;
    }
    else {
        return decrement(firstUnused);
    }
}

//*********************************************************************************
// releaseHeadChangeNote
//
// Mark the head node unused.
// This happens when the first change in the list is completely processed.
// That is, all interested parties have acknowledged it, and power is settled
// at the new level.
//*********************************************************************************

IOReturn IOPMchangeNoteList::releaseHeadChangeNote ( void )
{
    changeNote[firstInList].flags = IOPMNotInUse;
    firstInList = increment(firstInList);
    return IOPMNoErr;
}

//*********************************************************************************
// releaseTailChangeNote
//
// Mark the tail node unused.
// This happens when a power change is queued up after another which has
// not yet been started, and the second one supercedes the first.  The data in
// the second is copied into the first and the the second is released.  This
// collapses the first change out of the list.
//*********************************************************************************

IOReturn IOPMchangeNoteList::releaseTailChangeNote ( void )
{
    firstUnused = decrement(firstUnused);
    changeNote[firstUnused].flags = IOPMNotInUse;
    return IOPMNoErr;
}

//*********************************************************************************
// changeNoteInUse
//
//*********************************************************************************

bool IOPMchangeNoteList::changeNoteInUse ( unsigned long ordinal )
{
    if ( changeNote[ordinal].flags == IOPMNotInUse ) {
        return false;
    }
    else {
        return true;
    }
}

//*********************************************************************************
// nextChangeNote
//
// If the parameter corresponds to the most recent power change notification
// passed to drivers and children, return -1.  Otherwise, return the array
// position of the next notification in the circular list.
//*********************************************************************************

long IOPMchangeNoteList::nextChangeNote ( unsigned long ordinal )
{
    unsigned long i;

    i = increment(ordinal);
    if ( i == firstUnused)  {
        return -1;
    }
    return ( i );
}

//*********************************************************************************
// increment
//
// Increment the parameter mod the circular list size and return it.
//*********************************************************************************

unsigned long IOPMchangeNoteList::increment ( unsigned long ordinal )
{
    if ( ordinal == (IOPMMaxChangeNotes - 1) ) {
        return 0;
    }
    else {
        return ordinal + 1;
    }
}

//*********************************************************************************
// decrement
//
// Decrement the parameter mod the circular list size and return it.
//*********************************************************************************

unsigned long IOPMchangeNoteList::decrement ( unsigned long  ordinal )
{
    if ( ordinal == 0 ) {
        return IOPMMaxChangeNotes - 1;
    }
    else {
        return ordinal - 1;
    }
}

//*********************************************************************************
// previousChangeNote
//
// If the parameter corresponds to the oldest power change notification
// passed to drivers and children, return -1.  Otherwise, return the array
// position of the previous notification in the circular list.
//*********************************************************************************

long IOPMchangeNoteList::previousChangeNote ( unsigned long ordinal )
{
    if ( ordinal == firstInList )  {
        return -1;
    }
    return decrement(ordinal);
}

//*********************************************************************************
// listEmpty
//
//*********************************************************************************

bool IOPMchangeNoteList::listEmpty ( void )
{
    return ( firstInList == firstUnused ) ;
}
