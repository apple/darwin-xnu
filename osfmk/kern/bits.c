/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
 * @OSF_COPYRIGHT@
 */
/*
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:35  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.2  1998/04/29 17:35:55  mburg
 * MK7.3 merger
 *
 * Revision 1.1.24.1  1998/02/03  09:27:19  gdt
 * 	Merge up to MK7.3
 * 	[1998/02/03  09:12:57  gdt]
 *
 * Revision 1.1.21.1  1996/11/29  16:57:21  stephen
 * 	nmklinux_1.0b3_shared into pmk1.1
 * 	Added explanatory note.
 * 	[1996/04/10  16:54:46  emcmanus]
 * 
 * Revision 1.1.22.1  1997/06/17  02:57:05  devrcs
 * 	Added `testbit()' routine.
 * 	[1996/03/18  15:21:50  rkc]
 * 
 * Revision 1.1.7.3  1995/01/10  05:10:36  devrcs
 * 	mk6 CR801 - copyright marker not FREE_
 * 	[1994/12/01  19:24:54  dwm]
 * 
 * Revision 1.1.7.1  1994/06/14  16:59:49  bolinger
 * 	Merge up to NMK17.2.
 * 	[1994/06/14  16:53:29  bolinger]
 * 
 * Revision 1.1.5.1  1994/04/11  09:36:31  bernadat
 * 	Checked in NMK16_2 revision
 * 	[94/03/15            bernadat]
 * 
 * Revision 1.1.3.1  1993/12/23  08:53:13  bernadat
 * 	Checked in bolinger_860ci revision.
 * 	[93/11/29            bernadat]
 * 
 * Revision 1.1.1.2  1993/09/12  15:44:20  bolinger
 * 	Initial checkin of 860 modifications; MD files from NMK14.8.
 * 
 * $EndLog$
 */
/*
 * C version of bit manipulation routines now required by kernel.
 * Should be replaced with assembler versions in any real port.
 *
 * Note that these routines use little-endian numbering for bits (i.e.,
 * the bit number corresponds to the associated power-of-2).
 */
#include <mach/machine/vm_param.h>	/* for BYTE_SIZE */

#define INT_SIZE	(BYTE_SIZE * sizeof (int))

/*
 * Set indicated bit in bit string.
 */
void
setbit(int bitno, int *s)
{
	for ( ; INT_SIZE <= bitno; bitno -= INT_SIZE, ++s)
		;
	*s |= 1 << bitno;
}

/*
 * Clear indicated bit in bit string.
 */
void
clrbit(int bitno, int *s)
{
	for ( ; INT_SIZE <= bitno; bitno -= INT_SIZE, ++s)
		;
	*s &= ~(1 << bitno);
}

/*
 * Find first bit set in bit string.
 */
int
ffsbit(int *s)
{
	int offset, mask;

	for (offset = 0; !*s; offset += INT_SIZE, ++s)
		;
	for (mask = 1; mask; mask <<= 1, ++offset)
		if (mask & *s)
			return (offset);
	/*
	 * Shouldn't get here
	 */
	return (0);
}

/*
 * Test if indicated bit is set in bit string.
 */
int
testbit(int bitno, int *s)
{
	for ( ; INT_SIZE <= bitno; bitno -= INT_SIZE, ++s)
		;
	return(*s & (1 << bitno));
}
