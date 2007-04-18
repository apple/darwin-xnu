/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1982, 1986, 1989, 1991, 1993, 1995
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)ufs_ihash.c	8.7 (Berkeley) 5/17/95
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/vnode_internal.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/quota.h>

#include <ufs/ufs/quota.h>
#include <ufs/ufs/inode.h>
#include <ufs/ufs/ufs_extern.h>

/*
 * Structures associated with inode cacheing.
 */
LIST_HEAD(ihashhead, inode) *ihashtbl;
u_long	ihash;		/* size of hash table - 1 */
#define	INOHASH(device, inum)	(&ihashtbl[((device) + (inum)) & ihash])

/*
 * Initialize inode hash table.
 */
void
ufs_ihashinit()
{

	ihashtbl = hashinit(desiredvnodes, M_UFSMNT, &ihash);
}

/*
 * Use the device/inum pair to find the incore inode, and return a pointer
 * to it. If it is in core, return it, even if it is locked.
 */
struct vnode *
ufs_ihashlookup(dev, inum)
	dev_t dev;
	ino_t inum;
{
	struct inode *ip;

	for (ip = INOHASH(dev, inum)->lh_first; ip; ip = ip->i_hash.le_next)
		if (inum == ip->i_number && dev == ip->i_dev)
			break;
	if (ip)
		return (ITOV(ip));
	return (NULLVP);
}

/*
 * Use the device/inum pair to find the incore inode, and return a pointer
 * to it. If it is in core, but locked, wait for it.
 */
struct vnode *
ufs_ihashget(dev, inum)
	dev_t dev;
	ino_t inum;
{
	struct proc *p = current_proc();	/* XXX */
	struct inode *ip;
	struct vnode *vp;
	uint32_t vid;

loop:
	for (ip = INOHASH(dev, inum)->lh_first; ip; ip = ip->i_hash.le_next) {
		if (inum == ip->i_number && dev == ip->i_dev) {

			if (ISSET(ip->i_flag, IN_ALLOC)) {
				/*
				 * inode is being created. Wait for it
				 * to finish creation
				 */
				SET(ip->i_flag, IN_WALLOC);
				(void)tsleep((caddr_t)ip, PINOD, "ufs_ihashget", 0);
				goto loop;
			}

			if (ISSET(ip->i_flag, IN_TRANSIT)) {
				/*
				 * inode is getting reclaimed wait till
				 * the operation is complete and return
				 * error
				 */
				SET(ip->i_flag, IN_WTRANSIT);
				(void)tsleep((caddr_t)ip, PINOD, "ufs_ihashget1", 0);
				goto loop;
			}
			vp = ITOV(ip);
			/*
			 * the vid needs to be grabbed before we drop
			 * lock protecting the hash
			 */
			vid = vnode_vid(vp);

			/*
			 * we currently depend on running under the FS funnel
			 * when we do proper locking and advertise ourselves
			 * as thread safe, we'll need a lock to protect the
			 * hash lookup... this is where we would drop it
			 */
			if (vnode_getwithvid(vp, vid)) {
			        /*
				 * If vnode is being reclaimed, or has
				 * already changed identity, no need to wait
				 */
			        return (NULL);
			}
			return (vp);
		}
	}
	return (NULL);
}

/*
 * Insert the inode into the hash table,
 * inode is assumed to be locked by the caller
 */
void
ufs_ihashins(ip)
	struct inode *ip;
{
	struct ihashhead *ipp;

	ipp = INOHASH(ip->i_dev, ip->i_number);
	LIST_INSERT_HEAD(ipp, ip, i_hash);
}

/*
 * Remove the inode from the hash table.
 */
void
ufs_ihashrem(ip)
	struct inode *ip;
{
	LIST_REMOVE(ip, i_hash);
#if DIAGNOSTIC
	ip->i_hash.le_next = NULL;
	ip->i_hash.le_prev = NULL;
#endif
}
