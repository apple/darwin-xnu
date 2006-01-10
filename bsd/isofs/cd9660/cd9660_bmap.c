/*
 * Copyright (c) 2000-2003 Apple Computer, Inc. All rights reserved.
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
#include <sys/file.h>

#include <isofs/cd9660/iso.h>
#include <isofs/cd9660/cd9660_node.h>


/* blktooff converts a logical block number to a file offset */
int
cd9660_blktooff(struct vnop_blktooff_args *ap)
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
cd9660_offtoblk(struct vnop_offtoblk_args *ap)
{
	register struct iso_node *ip;
	register struct iso_mnt *imp;

	if (ap->a_vp == NULL)
		return (EINVAL);

	ip = VTOI(ap->a_vp);
	imp = ip->i_mnt;

	*ap->a_lblkno = (daddr64_t)lblkno(imp, ap->a_offset);
	return (0);
}

int
cd9660_blockmap(struct vnop_blockmap_args *ap)
{
	struct iso_node *ip = VTOI(ap->a_vp);
	size_t cbytes;
	int devBlockSize = 0;
	off_t offset = ap->a_foffset;

	/*
	 * Check for underlying vnode requests and ensure that logical
	 * to physical mapping is requested.
	 */
	if (ap->a_bpn == NULL)
		return (0);

	devBlockSize = vfs_devblocksize(vnode_mount(ap->a_vp));

	/*
	 * Associated files have an Apple Double header
	 */
	if (ip->i_flag & ISO_ASSOCIATED) {
		if (offset < ADH_SIZE) {
			if (ap->a_run)
				*ap->a_run = 0;
			*ap->a_bpn = (daddr64_t)-1;
			goto out;
		} else {
			offset -= ADH_SIZE;
		}
	}

	*ap->a_bpn = (daddr64_t)(ip->iso_start + lblkno(ip->i_mnt, offset));

	/*
	 * Determine maximum number of contiguous bytes following the
	 * requested offset.
	 */
	if (ap->a_run) {
		if (ip->i_size > offset)
			cbytes = ip->i_size - offset;
		else
			cbytes = 0;

		cbytes = (cbytes + (devBlockSize - 1)) & ~(devBlockSize - 1);

		*ap->a_run = MIN(cbytes, ap->a_size);
	};
out:
	if (ap->a_poff)
		*(int *)ap->a_poff = (long)offset & (devBlockSize - 1);

	return (0);	
}

