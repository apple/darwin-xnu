/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
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
/*
	File:		HFSUnicodeWrappers.h

	Contains:	IPI to Unicode routines used by File Manager.

	Version:	HFS Plus 1.0

	Written by:	Mark Day

	Copyright:	© 1996-1997 by Apple Computer, Inc., all rights reserved.

	File Ownership:

		DRI:				xxx put dri here xxx

		Other Contact:		xxx put other contact here xxx

		Technology:			xxx put technology here xxx

	Writers:

		(DSH)	Deric Horn
		(msd)	Mark Day
		(djb)	Don Brady

	Change History (most recent first):

	  <CS11>	11/16/97	djb		Change Unicode.h to UnicodeConverter.h.
	  <CS10>	 11/7/97	msd		Remove prototype for CompareUnicodeNames(). Add prototype for
									FastUnicodeCompare().
	   <CS9>	10/13/97	djb		Add encoding/index macros and add prototypes for new Get/Set
									encodding routines.
	   <CS8>	 9/15/97	djb		InitUnicodeConverter now takes a boolean.
	   <CS7>	 9/10/97	msd		Add prototype for InitializeEncodingContext.
	   <CS6>	 6/26/97	DSH		Include  "MockConverter" prototype for DFA usage.
	   <CS5>	 6/25/97	DSH		Removed Prototype definitions, and checked in Unicode.h and
									TextCommon.h from Julio Gonzales into InternalInterfaces.
	   <CS4>	 6/25/97	msd		Add prototypes for some new Unicode routines that haven't
									appeared in MasterInterfaces yet.
	   <CS3>	 6/18/97	djb		Add more ConversionContexts routines.
	   <CS2>	 6/13/97	djb		Switched to ConvertUnicodeToHFSName, ConvertHFSNameToUnicode, &
									CompareUnicodeNames.
	   <CS1>	 4/28/97	djb		first checked in
	  <HFS1>	12/12/96	msd		first checked in

*/
#ifndef _HFSUNICODEWRAPPERS_
#define _HFSUNICODEWRAPPERS_

#include <sys/appleapiopts.h>

#ifdef KERNEL
#ifdef __APPLE_API_PRIVATE

#include "../../hfs_macos_defs.h"
#include "../../hfs_format.h"


extern OSErr ConvertUnicodeToUTF8Mangled ( ByteCount srcLen,
									ConstUniCharArrayPtr srcStr,
									ByteCount maxDstLen,
					 				ByteCount *actualDstLen,
									unsigned char* dstStr ,
									HFSCatalogNodeID cnid);

/*
	This routine compares two Unicode names based on an ordering defined by the HFS Plus B-tree.
	This ordering must stay fixed for all time.
	
	Output:
		-n		name1 < name2	(i.e. name 1 sorts before name 2)
		 0		name1 = name2
		+n		name1 > name2
	
	NOTE: You should not depend on the magnitude of the result, just its sign.  That is, when name1 < name2, then any
	negative number may be returned.
*/

extern SInt32 FastUnicodeCompare(register ConstUniCharArrayPtr str1, register ItemCount length1,
								 register ConstUniCharArrayPtr str2, register ItemCount length2);


extern SInt32 FastRelString( ConstStr255Param str1, ConstStr255Param str2 );


extern HFSCatalogNodeID GetEmbeddedFileID( ConstStr31Param filename, UInt32 length, UInt32 *prefixLength );

#endif /* __APPLE_API_PRIVATE */
#endif /* KERNEL */
#endif /* _HFSUNICODEWRAPPERS_ */
