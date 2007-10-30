/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
/*	$NetBSD: cd9660_util.c,v 1.8 1994/12/13 22:33:25 mycroft Exp $	*/

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
 *	@(#)cd9660_util.c	8.3 (Berkeley) 12/5/94
 *
 * HISTORY
 *  7-Dec-98	Add ATTR_VOL_MOUNTFLAGS attribute support - djb
 * 18-Nov-98	Add support for volfs - djb
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/resourcevar.h>
#include <sys/kernel.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/buf.h>
#include <sys/proc.h>
#include <sys/kauth.h>
#include <sys/conf.h>
#include <sys/utfconv.h>
#include <miscfs/specfs/specdev.h> /* XXX */
#include <miscfs/fifofs/fifo.h> /* XXX */
#include <sys/malloc.h>
#include <sys/dir.h>
#include <sys/attr.h>
#include <kern/assert.h>

#include <isofs/cd9660/iso.h>
#include <isofs/cd9660/cd9660_node.h>
#include <isofs/cd9660/iso_rrip.h>

#include <libkern/OSByteOrder.h>

/*
 * translate and compare a filename
 * Note: Version number plus ';' may be omitted.
 */
int
isofncmp(u_char *fn, int fnlen, u_char *isofn, int isolen)
{
	int i, j;
	char c;
	
	while (--fnlen >= 0) {
		if (--isolen < 0)
			return *fn;
		if ((c = *isofn++) == ';') {
			switch (*fn++) {
			default:
				return *--fn;
			case 0:
				return 0;
			case ';':
				break;
			}
			for (i = 0; --fnlen >= 0; i = i * 10 + *fn++ - '0') {
				if (*fn < '0' || *fn > '9') {
					return -1;
				}
			}
			for (j = 0; --isolen >= 0; j = j * 10 + *isofn++ - '0');
			return i - j;
		}
		/* if raw comparison fails, check if char was mapped */
		if (c != *fn) {
			if (c >= 'A' && c <= 'Z') {
				if (c + ('a' - 'A') != *fn) {
					if (*fn >= 'a' && *fn <= 'z')
						return *fn - ('a' - 'A') - c;
					else
						return *fn - c;
				}
			} else if (c == '/') {
				if (*fn != ':')
					return *fn - c;
			} else if (c > 0 || *fn != '_')
				return *fn - c;
		}
		fn++;
	}
	if (isolen > 0) {
		switch (*isofn) {
		default:
			return -1;
		case '.':
			if (isofn[1] != ';')
				return -1;
		case ';':
			return 0;
		}
	}
	return 0;
}


/*
 * translate and compare a UCS-2 filename
 * Note: Version number plus ';' may be omitted.
 *
 * The name pointed to by "fn" is the search name, whose characters are
 * in native endian order.  The name "ucsfn" is the on-disk name, whose
 * characters are in big endian order.
 */

int
ucsfncmp(u_int16_t *fn, int fnlen, u_int16_t *ucsfn, int ucslen)
{
	int i, j;
	u_int16_t c;
	
	/* convert byte count to char count */
	ucslen /= 2;
	fnlen /= 2;

	while (--fnlen >= 0) {
		if (--ucslen < 0)
			return *fn;
		if ((c = OSSwapBigToHostInt16(*ucsfn++)) == UCS_SEPARATOR2) {
			switch (*fn++) {
			default:
				return *--fn;
			case 0:
				return 0;
			case UCS_SEPARATOR2:
				break;
			}
			for (i = 0; --fnlen >= 0; i = i * 10 + *fn++ - '0') {
				if (*fn < '0' || *fn > '9') {
					return -1;
				}
			}
			for (j = 0; --ucslen >= 0; j = j * 10 + OSSwapBigToHostInt16(*ucsfn++) - '0');
			return i - j;
		}
		if (c != *fn)
			return *fn - c;
		fn++;
	}
	if (ucslen > 0) {
		switch (*ucsfn) {
		default:
			return -1;
		case OSSwapHostToBigConstInt16(UCS_SEPARATOR1):
			if (ucsfn[1] != OSSwapHostToBigConstInt16(UCS_SEPARATOR2))
				return -1;
		case OSSwapHostToBigConstInt16(UCS_SEPARATOR2):
			return 0;
		}
	}
	return 0;
}


/*
 * translate a filename
 */
void
isofntrans(u_char *infn, int infnlen, u_char *outfn, u_short *outfnlen,
		int original, int assoc)
{
	int fnidx = 0;
	
	/*
	 * Add a "._" prefix for associated files
	 */
	if (assoc) {
		*outfn++ = ASSOCCHAR1;
		*outfn++ = ASSOCCHAR2;
		fnidx += 2;
		infnlen +=2;
	}
	for (; fnidx < infnlen; fnidx++) {
		char c = *infn++;
		
		/*
		 * Some ISO 9600 CD names contain 8-bit chars.
		 * These chars are mapped to '_' because there
		 * is no context for mapping them to UTF-8.
		 * In addition '/' is mapped to ':'.
		 *
		 * isofncmp accounts for these mappings.
		 */
		if (!original) {
			if (c < 0)
				c = '_';
			else if (c == '/')
				c = ':';
			else if (c == '.' && *infn == ';')
				break;
			else if (c == ';')
				break;
		}
		*outfn++ = c;
	}
	*outfnlen = fnidx;
}



/*
 * translate a UCS-2 filename to UTF-8
 */
void
ucsfntrans(u_int16_t *infn, int infnlen, u_char *outfn, u_short *outfnlen,
		int dir, int assoc)
{
	if (infnlen == 1) {
		strcpy(outfn, "..");

		if (*(u_char*)infn == 0)
			*outfnlen = 1;
		else if (*(u_char*)infn == 1) 
			*outfnlen = 2;
	} else {
		int fnidx;
		size_t outbytes;
		int flags;
		
		fnidx = infnlen/2;
		flags = 0;

		/*
		 * Add a "._" prefix for associated files
		 */
		if (assoc) {
			*outfn++ = ASSOCCHAR1;
			*outfn++ = ASSOCCHAR2;
		}
		if (!dir) {
			/* strip file version number */
			for (fnidx--; fnidx > 0; fnidx--) {
				/* stop when ';' is found */
				if (infn[fnidx] == OSSwapHostToBigConstInt16(UCS_SEPARATOR2)) {
					/* drop dangling dot */
					if (fnidx > 0 && infn[fnidx-1] == OSSwapHostToBigConstInt16(UCS_SEPARATOR1))
						fnidx--;
					break;
				}
			}
			if (fnidx <= 0)
				fnidx = infnlen/2;
		}

		flags = UTF_NO_NULL_TERM | UTF_DECOMPOSED | UTF_BIG_ENDIAN;

		(void) utf8_encodestr(infn, fnidx * 2, outfn, &outbytes, ISO_JOLIET_NAMEMAX, 0, flags);
		*outfnlen = assoc ? outbytes + 2 : outbytes;
	}
}


/*
 * count the number of children by enumerating the directory
 */
static int
isochildcount(struct vnode *vdp, int *dircnt, int *filcnt)
{
	struct iso_node *dp;
	struct buf *bp = NULL;
	struct iso_mnt *imp;
	struct iso_directory_record *ep;
	uint32_t bmask;
	int error = 0;
	int reclen;
	int dirs, files;
	int blkoffset;
	int logblksize;
	int32_t diroffset;

	dp = VTOI(vdp);
	imp = dp->i_mnt;
	bmask = imp->im_sector_size - 1;
	logblksize = imp->im_sector_size;
	blkoffset = diroffset = 0;
	dirs = files = 0;

	while (diroffset < dp->i_size) {
		/*
		 * If offset is on a block boundary, read the next 
		 * directory block. Release previous if it exists.
		 */
		if ((diroffset & bmask) == 0) {
			if (bp != NULL)
				buf_brelse(bp);
			if ( (error = cd9660_blkatoff(vdp, SECTOFF(imp, diroffset), NULL, &bp)) )
				break;
			blkoffset = 0;
		}

		ep = (struct iso_directory_record *)
			(buf_dataptr(bp) + blkoffset);

		reclen = isonum_711(ep->length);
		if (reclen == 0) {
			/* skip to next block, if any */
			diroffset =
			    (diroffset & ~bmask) + logblksize;
			continue;
		}

		if ((reclen < ISO_DIRECTORY_RECORD_SIZE)  ||
		    (blkoffset + reclen > logblksize)     ||
		    (reclen < ISO_DIRECTORY_RECORD_SIZE + isonum_711(ep->name_len))){
			/* illegal, so give up */
			break;
		}

		/*
		 * Some poorly mastered discs have an incorrect directory
		 * file size.  If the '.' entry has a better size (bigger)
		 * then use that instead.
		 */
		if ((diroffset == 0) && (isonum_733(ep->size) > dp->i_size)) {
			dp->i_size = isonum_733(ep->size);
		}

		if ( isonum_711(ep->flags) & directoryBit )
			dirs++;
		else if ((isonum_711(ep->flags) & associatedBit) == 0)
			files++;

		diroffset += reclen;
		blkoffset += reclen;
	}

	if (bp)
		buf_brelse (bp);

	*dircnt = dirs;
	*filcnt = files;

	return (error);
}


static uint32_t
DerivePermissionSummary(uid_t owner, gid_t group, mode_t obj_mode, __unused struct iso_mnt *imp)
{
    kauth_cred_t cred = kauth_cred_get();
    uint32_t permissions;
    int is_member;

     /* User id 0 (root) always gets access. */
     if (!suser(cred, NULL)) {
         permissions = R_OK | X_OK;
         goto Exit;
     };

    /* Otherwise, check the owner. */
    if (owner == kauth_cred_getuid(cred)) {
        permissions = ((uint32_t)obj_mode & S_IRWXU) >> 6;
        goto Exit;
    }

    /* Otherwise, check the groups. */
		if (kauth_cred_ismember_gid(cred, group, &is_member) == 0 && is_member) {
			permissions = ((uint32_t)obj_mode & S_IRWXG) >> 3;
			goto Exit;
		}

    /* Otherwise, settle for 'others' access. */
    permissions = (uint32_t)obj_mode & S_IRWXO;

Exit:
	return permissions & ~W_OK;    	/* Write access is always impossible */
}
