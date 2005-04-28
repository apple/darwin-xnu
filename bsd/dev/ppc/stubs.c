/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 1997 by Apple Computer, Inc., all rights reserved
 * Copyright (c) 1993 NeXT Computer, Inc.
 *
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/ioctl.h>
#include <sys/tty.h>
#include <sys/conf.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <kern/thread.h>
#include <kern/task.h>
#include <vm/vm_map.h>


/* 
 * copy a null terminated string from one point to another in 
 * the kernel address space.
 *   - no access checks are performed.
 *   - if the end of string isn't found before
 *     maxlen bytes are copied,  return ENAMETOOLONG,
 *     indicating an incomplete copy.
 *   - otherwise, return 0, indicating success.
 * the number of bytes copied is always returned in lencopied.
 */
/* from ppc/fault_copy.c -Titan1T4 VERSION  */
int
copystr(const void *vfrom, void *vto, size_t maxlen, size_t *lencopied)
{
    register unsigned l;
	caddr_t from, to;

	from = vfrom;
	to = vto;
    for (l = 0; l < maxlen; l++)
        if ((*to++ = *from++) == '\0') {
            if (lencopied)
                *lencopied = l + 1;
            return 0;
        }
    if (lencopied)
	*lencopied = maxlen;
    return ENAMETOOLONG;
}

int copywithin(src, dst, count)
void  * src, *dst;
size_t count;
{
	bcopy(src,dst,count);
	return 0;
}

void *
get_bsduthreadarg(thread_t th)
{
struct uthread *ut;
	ut = get_bsdthread_info(th);
	return((void *)(ut->uu_arg));
}

int *
get_bsduthreadrval(thread_t th)
{
struct uthread *ut;
	ut = get_bsdthread_info(th);
	return(&ut->uu_rval[0]);
}

