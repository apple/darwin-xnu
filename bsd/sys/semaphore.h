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
/*	@(#)semaphore.h	1.0	2/29/00		*/



/* 
 * semaphore.h - POSIX semaphores
 *
 * HISTORY
 * 29-Feb-00	A.Ramesh at Apple
 *	Created for Mac OS X
 */

#ifndef	_SYS_SEMAPHORE_H_
#define _SYS_SEMAPHORE_H_

typedef int sem_t;
/* this should go in limits.h> */
#define SEM_VALUE_MAX 32767
#define SEM_FAILED -1

#ifndef KERNEL
#include <sys/cdefs.h>

__BEGIN_DECLS
int sem_close(sem_t *);
int sem_destroy(sem_t *);
int sem_getvalue(sem_t *, int *);
int sem_init(sem_t *, int, unsigned int);
sem_t * sem_open(const char *, int, ...);
int sem_post(sem_t *);
int sem_trywait(sem_t *);
int sem_unlink(const char *);
int sem_wait(sem_t *);
__END_DECLS

#endif /* KERNEL */

#endif	/* _SYS_SEMAPHORE_H_ */
