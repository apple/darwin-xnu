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
 * Revision 1.1.1.1  1998/09/22 21:05:30  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:46  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.2.6.1  1994/09/23  02:40:51  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:42:00  ezf]
 *
 * Revision 1.2.2.2  1993/06/09  02:42:37  gm
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  21:17:34  jeffc]
 * 
 * Revision 1.2  1993/04/19  16:38:03  devrcs
 * 		Merge untyped ipc:
 * 		New names for the fields - the structure isn't changed
 * 		[1993/03/12  23:01:38  travos]
 * 		Extended NDR record to include version number(s)
 * 		[1993/03/05  23:10:21  travos]
 * 		a new NDR structure
 * 	 	1993/02/13  00:47:46  travos]
 * 		Created. [travos@osf.org]
 * 		[1993/01/27  11:21:44  rod]
 * 	[1993/03/16  13:23:15  rod]
 * 
 * $EndLog$
 */

#ifndef _NDR_H_
#define _NDR_H_

typedef struct {
    unsigned char       mig_vers;
    unsigned char       if_vers;
    unsigned char       reserved1;
    unsigned char       mig_encoding;
    unsigned char       int_rep;
    unsigned char       char_rep;
    unsigned char       float_rep;
    unsigned char       reserved2;
} NDR_record_t;

/*
 * MIG supported protocols for Network Data Representation
 */
#define  NDR_PROTOCOL_2_0      0

/*
 * NDR 2.0 format flag type definition and values.
 */
#define  NDR_INT_BIG_ENDIAN    0
#define  NDR_INT_LITTLE_ENDIAN 1
#define  NDR_FLOAT_IEEE        0
#define  NDR_FLOAT_VAX         1
#define  NDR_FLOAT_CRAY        2
#define  NDR_FLOAT_IBM         3
#define  NDR_CHAR_ASCII        0
#define  NDR_CHAR_EBCDIC       1

extern NDR_record_t NDR_record;

#endif /* _NDR_H_ */
