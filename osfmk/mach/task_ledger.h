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
 * Revision 1.1.8.2  1995/01/06  19:51:54  devrcs
 * 	mk6 CR668 - 1.3b26 merge
 * 	[1994/10/14  03:43:13  dwm]
 *
 * Revision 1.1.8.1  1994/09/23  02:42:55  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:43:00  ezf]
 * 
 * Revision 1.1.4.3  1993/09/17  21:35:29  robert
 * 	change marker to OSF_FREE_COPYRIGHT
 * 	[1993/09/17  21:28:49  robert]
 * 
 * Revision 1.1.4.2  1993/06/04  15:13:57  jeffc
 * 	CR9193 - MK5.0 merge.
 * 	[1993/05/18  02:38:04  gm]
 * 
 * Revision 3.0.2.2  1993/05/15  15:42:19  jph
 * 	Merge MK5.0: change LEDGER_REAL_ITEMS to be LEDGER_N_ITEMS.
 * 	[1993/05/15  15:21:21  jph]
 * 
 * Revision 3.0  1992/12/31  22:13:53  ede
 * 	Initial revision for OSF/1 R1.3
 * 
 * Revision 1.2  1991/08/15  19:16:53  devrcs
 * 	Ledgers: indices for task_ledger exported routines.
 * 	[91/07/18  11:04:31  dwm]
 * 
 * $EndLog$
 */

/*
 * Definitions for task ledger line items
 */
#define ITEM_THREADS		0	/* number of threads	*/
#define ITEM_TASKS		1	/* number of tasks	*/

#define ITEM_VM	   		2	/* virtual space (bytes)*/

#define LEDGER_N_ITEMS		3	/* Total line items	*/

#define LEDGER_UNLIMITED	0	/* ignored item.maximum	*/
