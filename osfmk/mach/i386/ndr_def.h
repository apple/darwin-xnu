/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
/*
 * @OSF_COPYRIGHT@
 */
/*
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:31  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:38  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.2.6.1  1994/09/23  01:59:33  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:25:24  ezf]
 *
 * Revision 1.2.2.2  1993/06/09  02:29:06  gm
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  21:06:33  jeffc]
 * 
 * Revision 1.2  1993/04/19  16:15:32  devrcs
 * 		Untyped ipc merge:
 * 		New names for the fields - the structure isn't changed
 * 		[1993/03/12  23:01:28  travos]
 * 		Extended NDR record to include version number(s)
 * 		[1993/03/05  23:09:51  travos]
 * 		It initializes the NDR record. Included also by libmach
 * 		[1993/02/17  21:58:01  travos]
 * 	[1993/03/16  13:42:33  rod]
 * 
 * $EndLog$
 */


/* NDR record for Intel x86s */

#include <mach/ndr.h>

NDR_record_t NDR_record = {
	0,			/* mig_reserved */
	0,			/* mig_reserved */
	0,			/* mig_reserved */
	NDR_PROTOCOL_2_0,		
	NDR_INT_LITTLE_ENDIAN,
	NDR_CHAR_ASCII,
	NDR_FLOAT_IEEE,
	0,
};
