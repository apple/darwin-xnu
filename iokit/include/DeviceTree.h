/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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
#ifndef __DEVICE_TREE__
#define __DEVICE_TREE__

#ifdef __cplusplus
extern "C" {
#endif

/*
------------------------------------------------------------------------------------
 Foundation Types
------------------------------------------------------------------------------------
*/
enum {
	kDTPathNameSeparator		= '/'				/* 0x2F */
};


/* Property Name Definitions (Property Names are C-Strings)*/
enum {
	kDTMaxPropertyNameLength	= 31				/* Max length of Property Name (terminator not included) */
};

typedef char DTPropertyNameBuf[32];


/* Entry Name Definitions (Entry Names are C-Strings)*/
enum {
	kDTMaxEntryNameLength		= 31				/* Max length of a C-String Entry Name (terminator not included) */
};

/* length of DTEntryNameBuf = kDTMaxEntryNameLength +1*/
typedef char DTEntryNameBuf[32];


/* Entry*/
typedef struct OpaqueDTEntry* DTEntry;

/* Entry Iterator*/
typedef struct OpaqueDTEntryIterator* DTEntryIterator;

/* Property Iterator*/
typedef struct OpaqueDTPropertyIterator* DTPropertyIterator;


/* status values*/
enum {
		kError = -1,
		kIterationDone = 0,
		kSuccess = 1
};

/*
------------------------------------------------------------------------------------
 Device Tree Calls
------------------------------------------------------------------------------------
*/

/*
------------------------------------------------------------------------------------
 Entry Handling
------------------------------------------------------------------------------------
*/
/* Compare two Entry's for equality. */
extern int DTEntryIsEqual(const DTEntry ref1, const DTEntry ref2);

/*
------------------------------------------------------------------------------------
 LookUp Entry by Name
------------------------------------------------------------------------------------
*/
/*
 Lookup Entry
 Locates an entry given a specified subroot (searchPoint) and path name.  If the
 searchPoint pointer is NULL, the path name is assumed to be an absolute path
 name rooted to the root of the device tree.
*/
extern int DTLookupEntry(const DTEntry searchPoint, const char *pathName, DTEntry *foundEntry);

/*
------------------------------------------------------------------------------------
 Entry Iteration
------------------------------------------------------------------------------------
*/
/*
 An Entry Iterator maintains three variables that are of interest to clients.
 First is an "OutermostScope" which defines the outer boundry of the iteration.
 This is defined by the starting entry and includes that entry plus all of it's
 embedded entries. Second is a "currentScope" which is the entry the iterator is
 currently in. And third is a "currentPosition" which is the last entry returned
 during an iteration.

 Create Entry Iterator
 Create the iterator structure. The outermostScope and currentScope of the iterator
 are set to "startEntry".  If "startEntry" = NULL, the outermostScope and
 currentScope are set to the root entry.  The currentPosition for the iterator is
 set to "nil".
*/
extern int DTCreateEntryIterator(const DTEntry startEntry, DTEntryIterator *iterator);

/* Dispose Entry Iterator*/
extern int DTDisposeEntryIterator(DTEntryIterator iterator);

/*
 Enter Child Entry
 Move an Entry Iterator into the scope of a specified child entry.  The
 currentScope of the iterator is set to the entry specified in "childEntry".  If
 "childEntry" is nil, the currentScope is set to the entry specified by the
 currentPosition of the iterator.
*/
extern int DTEnterEntry(DTEntryIterator iterator, DTEntry childEntry);

/*
 Exit to Parent Entry
 Move an Entry Iterator out of the current entry back into the scope of it's parent
 entry. The currentPosition of the iterator is reset to the current entry (the
 previous currentScope), so the next iteration call will continue where it left off.
 This position is returned in parameter "currentPosition".
*/
extern int DTExitEntry(DTEntryIterator iterator, DTEntry *currentPosition);

/*
 Iterate Entries 
 Iterate and return entries contained within the entry defined by the current
 scope of the iterator.  Entries are returned one at a time. When
 int == kIterationDone, all entries have been exhausted, and the
 value of nextEntry will be Nil. 
*/
extern int DTIterateEntries(DTEntryIterator iterator, DTEntry *nextEntry);

/*
 Restart Entry Iteration
 Restart an iteration within the current scope.  The iterator is reset such that
 iteration of the contents of the currentScope entry can be restarted. The
 outermostScope and currentScope of the iterator are unchanged. The currentPosition
 for the iterator is set to "nil".
*/
extern int DTRestartEntryIteration(DTEntryIterator iterator);

/*
------------------------------------------------------------------------------------
 Get Property Values
------------------------------------------------------------------------------------
*/
/*
 Get the value of the specified property for the specified entry.  

 Get Property
*/
extern int DTGetProperty(const DTEntry entry, const char *propertyName, void **propertyValue, int *propertySize);

/*
------------------------------------------------------------------------------------
 Iterating Properties
------------------------------------------------------------------------------------
*/
/*
 Create Property Iterator
 Create the property iterator structure. The target entry is defined by entry.
*/
extern int DTCreatePropertyIterator(const DTEntry entry, DTPropertyIterator *iterator);

/* Dispose Property Iterator*/
extern int DTDisposePropertyIterator(DTPropertyIterator iterator);

/*
 Iterate Properites
 Iterate and return properties for given entry.  
 When int == kIterationDone, all properties have been exhausted.
*/
extern int DTIterateProperties(DTPropertyIterator iterator, char **foundProperty);

/*
 Restart Property Iteration
 Used to re-iterate over a list of properties.  The Property Iterator is reset to
 the beginning of the list of properties for an entry.
*/
extern int DTRestartPropertyIteration(DTPropertyIterator iterator);

#ifdef __cplusplus
}
#endif

#endif /* __DEVICE_TREE__ */

