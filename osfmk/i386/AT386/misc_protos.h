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

#ifndef	_AT386_MISC_PROTOS_H_
#define	_AT386_MISC_PROTOS_H_

#include <pexpert/i386/boot.h>	/* for KernelBootArgs_t */

/*
 * i386/AT386/model_dep.c
 */

extern void		i386_init(void);
extern void		machine_init(void);
extern void		machine_startup(void);

/*
 * i386/AT386/kd.c
 */

extern void		cninit(void);
extern void		kdreboot(void);

/*
 * i386/db_interface.c
 */

extern void		kdb_console(void);

/*
 * i386/bcopy.s
 */

extern void		bcopy16(
				char		* from,
				char		* to,
				int		count);

typedef	void		(*i386_intr_t)(void);
#endif

