/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 */
/* 
 * Copyright (c) 1990, 1991 The University of Utah and
 * the Center for Software Science at the University of Utah (CSS).
 * All rights reserved.
 *
 * Permission to use, copy, modify and distribute this software is hereby
 * granted provided that (1) source code retains these copyright, permission,
 * and disclaimer notices, and (2) redistributions including binaries
 * reproduce the notices in supporting documentation, and (3) all advertising
 * materials mentioning features or use of this software display the following
 * acknowledgement: ``This product includes software developed by the Center
 * for Software Science at the University of Utah.''
 *
 * THE UNIVERSITY OF UTAH AND CSS ALLOW FREE USE OF THIS SOFTWARE IN ITS "AS
 * IS" CONDITION.  THE UNIVERSITY OF UTAH AND CSS DISCLAIM ANY LIABILITY OF
 * ANY KIND FOR ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * CSS requests users of this software to return to css-dist@cs.utah.edu any
 * improvements that they make and grant CSS redistribution rights.
 *
 * 	Utah $Hdr: machparam.h 1.7 92/05/22$
 */

#ifndef _PPC_MACHPARAM_H_
#define _PPC_MACHPARAM_H_

/*
 * Machine dependent constants for ppc. 
 * Added as needed (for device drivers).
 */
#define	NBPG	4096		/* bytes/page */
#define	PGSHIFT	12		/* LOG2(NBPG) */

#define DEV_BSHIFT      10               /* log2(DEV_BSIZE) */

/*
 * Disk devices do all IO in 1024-byte blocks.
 */
#define	DEV_BSIZE	1024

#define	btop(x)	((x)>>PGSHIFT)
#define	ptob(x)	((x)<<PGSHIFT)

/* Clicks to disk blocks */
#define ctod(x) ((x)<<(PGSHIFT-DEV_BSHIFT))

/* Disk blocks to clicks */
#define       dtoc(x) ((x)>>(PGSHIFT-DEV_BSHIFT))

/* clicks to bytes */
#define       ctob(x) ((x)<<PGSHIFT)

/* bytes to clicks */
#define       btoc(x) (((unsigned)(x)+(NBPG-1))>>PGSHIFT)

#endif /* _PPC_MACHPARAM_H_ */
