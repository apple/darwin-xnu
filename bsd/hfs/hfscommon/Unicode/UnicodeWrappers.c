/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
/*
	File:		UnicodeWrappers.c

	Contains:	Wrapper routines for Unicode conversion and comparison.

*/
#include <sys/param.h>
#include <sys/utfconv.h>

#include "../../hfs_macos_defs.h"
#include "UCStringCompareData.h"

#include "../headers/FileMgrInternal.h"
#include "../headers/HFSUnicodeWrappers.h"

enum {
	kMinFileExtensionChars = 1,	/* does not include dot */
	kMaxFileExtensionChars = 5	/* does not include dot */
};


#define EXTENSIONCHAR(c)	(((c) >= 0x61 && (c) <= 0x7A) || \
				 ((c) >= 0x41 && (c) <= 0x5A) || \
				 ((c) >= 0x30 && (c) <= 0x39))


#define IsHexDigit(c)		(((c) >= (UInt8) '0' && (c) <= (UInt8) '9') || \
				 ((c) >= (UInt8) 'A' && (c) <= (UInt8) 'F'))


static void	GetFilenameExtension( ItemCount length, ConstUniCharArrayPtr unicodeStr, char* extStr );

static void	GetFileIDString( HFSCatalogNodeID fileID, char* fileIDStr );

static UInt32	HexStringToInteger( UInt32 length, const UInt8 *hexStr );



/*
 * Convert file ID into a hexidecimal string with no leading zeros
 */
static void
GetFileIDString( HFSCatalogNodeID fileID, char * fileIDStr )
{
	SInt32	i, b;
	UInt8	*translate = (UInt8 *) "0123456789ABCDEF";
	UInt8	c;
	
	fileIDStr[0] = '#';

	for ( i = 0, b = 28; b >= 0; b -= 4 ) {
		c = *(translate + ((fileID >> b) & 0x0000000F));
		
		/* if its not a leading zero add it to our string */
		if ( (c != (UInt8) '0') || (i > 1) || (b == 0) )
			fileIDStr[++i] = c;
	}

	fileIDStr[++i] = '\0';
}


/*
 * Get filename extension (if any) as a C string
 */
static void
GetFilenameExtension(ItemCount length, ConstUniCharArrayPtr unicodeStr, char * extStr)
{
	UInt32	i;
	UniChar	c;
	UInt16	extChars;	/* number of extension chars (excluding dot) */
	UInt16	maxExtChars;
	Boolean	foundExtension;

	extStr[0] = '\0';	/* assume there's no extension */

	if ( length < 3 )
		return;		/* "x.y" is smallest possible extension */
	
	if ( length < (kMaxFileExtensionChars + 2) )
		maxExtChars = length - 2;	/* save room for prefix + dot */
	else
		maxExtChars = kMaxFileExtensionChars;

	i = length;
	extChars = 0;
	foundExtension = false;

	while ( extChars <= maxExtChars ) {
		c = unicodeStr[--i];

		/* look for leading dot */
		if ( c == (UniChar) '.' ) {
			if ( extChars > 0 )	/* cannot end with a dot */
				foundExtension = true;
			break;
		}

		if ( EXTENSIONCHAR(c) )
			++extChars;
		else
			break;
	}
	
	/* if we found one then copy it */
	if ( foundExtension ) {
		UInt8 *extStrPtr = extStr;
		const UniChar *unicodeStrPtr = &unicodeStr[i];
		
		for ( i = 0; i <= extChars; ++i )
			*(extStrPtr++) = (UInt8) *(unicodeStrPtr++);
		extStr[extChars + 1] = '\0';	/* terminate extension + dot */
	}
}



/*
 * Count filename extension characters (if any)
 */
static UInt32
CountFilenameExtensionChars( const unsigned char * filename, UInt32 length )
{
	UInt32	i;
	UniChar	c;
	UInt32	extChars;	/* number of extension chars (excluding dot) */
	UInt16	maxExtChars;
	Boolean	foundExtension;

	if (length == kUndefinedStrLen)
		length = strlen(filename);

	if ( length < 3 )
		return 0;	/* "x.y" is smallest possible extension	*/
	
	if ( length < (kMaxFileExtensionChars + 2) )
		maxExtChars = length - 2;	/* save room for prefix + dot */
	else
		maxExtChars = kMaxFileExtensionChars;

	extChars = 0;		/* assume there's no extension */
	i = length - 1;		/* index to last ascii character */
	foundExtension = false;

	while ( extChars <= maxExtChars ) {
		c = filename[i--];

		/* look for leading dot */
		if ( c == (UInt8) '.' )	{
			if ( extChars > 0 )	/* cannot end with a dot */
				return (extChars);

			break;
		}

		if ( EXTENSIONCHAR(c) )
			++extChars;
		else
			break;
	}
	
	return 0;
}


/*
 * extract the file id from a mangled name
 */
HFSCatalogNodeID
GetEmbeddedFileID(const unsigned char * filename, UInt32 length, UInt32 *prefixLength)
{
	short	extChars;
	short	i;
	UInt8	c;

	*prefixLength = 0;

	if ( filename == NULL )
		return 0;

	if (length == kUndefinedStrLen)
		length = strlen(filename);

	if ( length < 28 )
		return 0;	/* too small to have been mangled */

	/* big enough for a file ID (#10) and an extension (.x) ? */
	if ( length > 5 )
		extChars = CountFilenameExtensionChars(filename, length);
	else
		extChars = 0;

	/* skip over dot plus extension characters */
	if ( extChars > 0 )
		length -= (extChars + 1);	

	/* scan for file id digits */
	for ( i = length - 1; i >= 0; --i) {
		c = filename[i];

		/* look for file ID marker */
		if ( c == '#' ) {
			if ( (length - i) < 3 )
				break;	/* too small to be a file ID */

			*prefixLength = i;
			return HexStringToInteger(length - i - 1, &filename[i+1]);
		}

		if ( !IsHexDigit(c) )
			break;	/* file ID string must have hex digits */
	}

	return 0;
}



static UInt32
HexStringToInteger(UInt32 length, const UInt8 *hexStr)
{
	UInt32		value;
	short		i;
	UInt8		c;
	const UInt8	*p;

	value = 0;
	p = hexStr;

	for ( i = 0; i < length; ++i ) {
		c = *p++;

		if (c >= '0' && c <= '9') {
			value = value << 4;
			value += (UInt32) c - (UInt32) '0';
		} else if (c >= 'A' && c <= 'F') {
			value = value << 4;
			value += 10 + ((unsigned int) c - (unsigned int) 'A');
		} else {
			return 0;	/* bad character */
		}
	}

	return value;
}


/*
 * Routine:	FastRelString
 *
 * Output:	returns -1 if str1 < str2
 *		returns  1 if str1 > str2
 *		return	 0 if equal
 *
 */
extern unsigned short gCompareTable[];

SInt32	FastRelString( ConstStr255Param str1, ConstStr255Param str2 )
{
	UInt16*			compareTable;
	SInt32	 		bestGuess;
	UInt8 	 		length, length2;
	UInt8 	 		delta;

	delta = 0;
	length = *(str1++);
	length2 = *(str2++);

	if (length == length2)
		bestGuess = 0;
	else if (length < length2)
	{
		bestGuess = -1;
		delta = length2 - length;
	}
	else
	{
		bestGuess = 1;
		length = length2;
	}

	compareTable = (UInt16*) gCompareTable;

	while (length--)
	{
		UInt8	aChar, bChar;

		aChar = *(str1++);
		bChar = *(str2++);
		
		if (aChar != bChar)		//	If they don't match exacly, do case conversion
		{	
			UInt16	aSortWord, bSortWord;

			aSortWord = compareTable[aChar];
			bSortWord = compareTable[bChar];

			if (aSortWord > bSortWord)
				return 1;

			if (aSortWord < bSortWord)
				return -1;
		}
		
		//	If characters match exactly, then go on to next character immediately without
		//	doing any extra work.
	}
	
	//	if you got to here, then return bestGuess
	return bestGuess;
}	



//
//	FastUnicodeCompare - Compare two Unicode strings; produce a relative ordering
//
//	    IF				RESULT
//	--------------------------
//	str1 < str2		=>	-1
//	str1 = str2		=>	 0
//	str1 > str2		=>	+1
//
//	The lower case table starts with 256 entries (one for each of the upper bytes
//	of the original Unicode char).  If that entry is zero, then all characters with
//	that upper byte are already case folded.  If the entry is non-zero, then it is
//	the _index_ (not byte offset) of the start of the sub-table for the characters
//	with that upper byte.  All ignorable characters are folded to the value zero.
//
//	In pseudocode:
//
//		Let c = source Unicode character
//		Let table[] = lower case table
//
//		lower = table[highbyte(c)]
//		if (lower == 0)
//			lower = c
//		else
//			lower = table[lower+lowbyte(c)]
//
//		if (lower == 0)
//			ignore this character
//
//	To handle ignorable characters, we now need a loop to find the next valid character.
//	Also, we can't pre-compute the number of characters to compare; the string length might
//	be larger than the number of non-ignorable characters.  Further, we must be able to handle
//	ignorable characters at any point in the string, including as the first or last characters.
//	We use a zero value as a sentinel to detect both end-of-string and ignorable characters.
//	Since the File Manager doesn't prevent the NUL character (value zero) as part of a filename,
//	the case mapping table is assumed to map u+0000 to some non-zero value (like 0xFFFF, which is
//	an invalid Unicode character).
//
//	Pseudocode:
//
//		while (1) {
//			c1 = GetNextValidChar(str1)			//	returns zero if at end of string
//			c2 = GetNextValidChar(str2)
//
//			if (c1 != c2) break					//	found a difference
//
//			if (c1 == 0)						//	reached end of string on both strings at once?
//				return 0;						//	yes, so strings are equal
//		}
//
//		// When we get here, c1 != c2.  So, we just need to determine which one is less.
//		if (c1 < c2)
//			return -1;
//		else
//			return 1;
//

extern UInt16 gLowerCaseTable[];
extern UInt16 gLatinCaseFold[];

SInt32 FastUnicodeCompare ( register ConstUniCharArrayPtr str1, register ItemCount length1,
							register ConstUniCharArrayPtr str2, register ItemCount length2)
{
	register UInt16		c1,c2;
	register UInt16		temp;
	register UInt16*	lowerCaseTable;

	lowerCaseTable = (UInt16*) gLowerCaseTable;

	while (1) {
		/* Set default values for c1, c2 in case there are no more valid chars */
		c1 = 0;
		c2 = 0;
		
		/* Find next non-ignorable char from str1, or zero if no more */
		while (length1 && c1 == 0) {
			c1 = *(str1++);
			--length1;
			/* check for basic latin first */
			if (c1 < 0x0100) {
				c1 = gLatinCaseFold[c1];
				break;
			}
			/* case fold if neccessary */
			if ((temp = lowerCaseTable[c1>>8]) != 0)
				c1 = lowerCaseTable[temp + (c1 & 0x00FF)];
		}
		
		
		/* Find next non-ignorable char from str2, or zero if no more */
		while (length2 && c2 == 0) {
			c2 = *(str2++);
			--length2;
			/* check for basic latin first */
			if (c2 < 0x0100) {
				c2 = gLatinCaseFold[c2];
				break;
			}
			/* case fold if neccessary */
			if ((temp = lowerCaseTable[c2>>8]) != 0)
				c2 = lowerCaseTable[temp + (c2 & 0x00FF)];
		}
		
		if (c1 != c2)		//	found a difference, so stop looping
			break;
		
		if (c1 == 0)		//	did we reach the end of both strings at the same time?
			return 0;		//	yes, so strings are equal
	}
	
	if (c1 < c2)
		return -1;
	else
		return 1;
}


OSErr
ConvertUnicodeToUTF8Mangled(ByteCount srcLen, ConstUniCharArrayPtr srcStr, ByteCount maxDstLen,
					 ByteCount *actualDstLen, unsigned char* dstStr, HFSCatalogNodeID cnid)
{
	ByteCount subMaxLen;
	size_t utf8len;
	char fileIDStr[15];
	char extStr[15];

	GetFileIDString(cnid, fileIDStr);
	GetFilenameExtension(srcLen/sizeof(UniChar), srcStr, extStr);

	/* remove extension chars from source */
	srcLen -= strlen(extStr) * sizeof(UniChar);
	subMaxLen = maxDstLen - (strlen(extStr) + strlen(fileIDStr));

	(void) utf8_encodestr(srcStr, srcLen, dstStr, &utf8len, subMaxLen, ':', 0);

	strcat(dstStr, fileIDStr);
	strcat(dstStr, extStr);
	*actualDstLen = utf8len + (strlen(extStr) + strlen(fileIDStr));

	return noErr;
}

