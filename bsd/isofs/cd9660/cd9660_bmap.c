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
/*	$NetBSD: cd9660_bmap.c,v 1.5 1994/12/13 22:33:12 mycroft Exp $	*/

/*-
 * Copyright (c) 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley
 * by Pace Willisson (pace@blitz.com).  The Rock Ridge Extension
 * Support code is derived from software contributed to Berkeley
 * by Atsushi Murai (amurai@spec.co.jp).
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
 *	@(#)cd9660_bmap.c	8.4 (Berkeley) 12/5/94
 */

#include <sys/param.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/buf.h>
#include <sys/file.h>

#include <isofs/cd9660/iso.h>
#include <isofs/cd9660/cd9660_node.h>

/*
 * Bmap converts the logical block number of a file to its physical block
 * number on the disk. The conversion is done by using the logical block
 * number to index into the data block (extent) for the file.
 */
int
cd9660_bmap(ap)
	struct vop_bmap_args /* {
		struct vnode *a_vp;
		daddr_t  a_bn;
		struct vnode **a_vpp;
		daddr_t *a_bnp;
		int *a_runp;
	} */ *ap;
{
	struct iso_node *ip = VTOI(ap->a_vp);
	daddr_t lblkno = ap->a_bn;
	int bshift;

	/*
	 * Check for underlying vnode requests and ensure that logical
	 * to physical mapping is requested.
	 */
	if (ap->a_vpp != NULL)
		*ap->a_vpp = ip->i_devvp;
	if (ap->a_bnp == NULL)
		return (0);

	/*
	 * Compute the requested block number
	 */
	bshift = ip->i_mnt->im_bshift;
	*ap->a_bnp = (ip->iso_start + lblkno);

	/*
	 * Determine maximum number of readahead blocks following the
	 * requested block.
	 */
	if (ap->a_runp) {
		int nblk;

		nblk = (ip->i_size >> bshift) - (lblkno + 1);
		if (nblk <= 0)
			*ap->a_runp = 0;
		else if (nblk >= (MAXBSIZE >> bshift))
			*ap->a_runp = (MAXBSIZE >> bshift) - 1;
		else
			*ap->a_runp = nblk;
	}

	return (0);
}

/* blktooff converts a logical block number to a file offset */
int
cd9660_blktooff(ap)
	struct vop_blktooff_args /* {
		struct vnode *a_vp;
		daddr_t a_lblkno;
		off_t *a_offset;    
	} */ *ap;
{
	register struct iso_node *ip;
    register struct iso_mnt *imp;

	if (ap->a_vp == NULL)
		return (EINVAL);

	ip = VTOI(ap->a_vp);
	imp = ip->i_mnt;

	*ap->a_offset = (off_t)lblktosize(imp, ap->a_lblkno);
	return (0);
}

/* offtoblk converts a file offset to a logical block number */
int
cd9660_offtoblk(ap)
struct vop_offtoblk_args /* {
	struct vnode *a_vp;
	off_t a_offset;    
	daddr_t *a_lblkno;
	} */ *ap;
{
	register struct iso_node *ip;
	register struct iso_mnt *imp;

	if (ap->a_vp == NULL)
		return (EINVAL);

	ip = VTOI(ap->a_vp);
	imp = ip->i_mnt;

	*ap->a_lblkno = (daddr_t)lblkno(imp, ap->a_offset);
	return (0);
}

int
cd9660_cmap(ap)
struct vop_cmap_args /* {
	struct vnode *a_vp;
	off_t a_offset;    
	size_t a_size;
	daddr_t *a_bpn;
	size_t *a_run;
	void *a_poff;
} */ *ap;
{
	struct iso_node *ip = VTOI(ap->a_vp);
	size_t cbytes;
	int devBlockSize = 0;

	/*
	 * Check for underlying vnode requests and ensure that logical
	 * to physical mapping is requested.
	 */
	if (ap->a_bpn == NULL)
		return (0);

	VOP_DEVBLOCKSIZE(ip->i_devvp, &devBlockSize);

	*ap->a_bpn = (daddr_t)(ip->iso_start + lblkno(ip->i_mnt, ap->a_foffset));

	/*
	 * Determine maximum number of contiguous bytes following the
	 * requested offset.
	 */
	if (ap->a_run) {
		if (ip->i_size > ap->a_foffset)
			cbytes = ip->i_size - ap->a_foffset;
		else
			cbytes = 0;

		cbytes = (cbytes + (devBlockSize - 1)) & ~(devBlockSize - 1);

		*ap->a_run = MIN(cbytes, ap->a_size);
	};

	if (ap->a_poff)
		*(int *)ap->a_poff = (long)ap->a_foffset & (devBlockSize - 1);

	return (0);	
}

