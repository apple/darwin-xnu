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
#include <libkern/c++/OSObject.h>
#include <IOKit/IOReturn.h>

class IOPMinformee;
class IOService;

class IOPMinformeeList : public OSObject
{
OSDeclareDefaultStructors(IOPMinformeeList)

private:
IOPMinformee *	 firstItem;		// pointer to first informee in the list
unsigned long	length;			// how many informees are in the list


public:
void initialize ( void );

IOReturn addToList ( IOPMinformee *   newInformee );

IOPMinformee * firstInList ( void );

IOPMinformee * nextInList ( IOPMinformee * currentItem );

unsigned long numberOfItems ( void );

IOPMinformee * findItem ( IOService * driverOrChild );

IOReturn removeFromList ( IOService * theItem );

void free ( void );
};

