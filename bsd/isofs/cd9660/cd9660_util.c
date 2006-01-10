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
#include <architecture/byte_order.h>

#include <isofs/cd9660/iso.h>
#include <isofs/cd9660/cd9660_node.h>
#include <isofs/cd9660/iso_rrip.h>

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
		if ((c = *ucsfn++) == UCS_SEPARATOR2) {
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
			for (j = 0; --ucslen >= 0; j = j * 10 + *ucsfn++ - '0');
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
		case UCS_SEPARATOR1:
			if (ucsfn[1] != UCS_SEPARATOR2)
				return -1;
		case UCS_SEPARATOR2:
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
				if (infn[fnidx] == UCS_SEPARATOR2) {
					/* drop dangling dot */
					if (fnidx > 0 && infn[fnidx-1] == UCS_SEPARATOR1)
						fnidx--;
					break;
				}
			}
			if (fnidx <= 0)
				fnidx = infnlen/2;
		}

		flags = UTF_NO_NULL_TERM | UTF_DECOMPOSED;
		if (BYTE_ORDER != BIG_ENDIAN)
			flags |= UTF_REVERSE_ENDIAN;

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


int
attrcalcsize(struct attrlist *attrlist)
{
	int size;
	attrgroup_t a;
	boolean_t is_64_bit = proc_is64bit(current_proc());
	
#if ((ATTR_CMN_NAME			| ATTR_CMN_DEVID			| ATTR_CMN_FSID 			| ATTR_CMN_OBJTYPE 		| \
      ATTR_CMN_OBJTAG		| ATTR_CMN_OBJID			| ATTR_CMN_OBJPERMANENTID	| ATTR_CMN_PAROBJID		| \
      ATTR_CMN_SCRIPT		| ATTR_CMN_CRTIME			| ATTR_CMN_MODTIME			| ATTR_CMN_CHGTIME		| \
      ATTR_CMN_ACCTIME		| ATTR_CMN_BKUPTIME			| ATTR_CMN_FNDRINFO			| ATTR_CMN_OWNERID		| \
      ATTR_CMN_GRPID		| ATTR_CMN_ACCESSMASK		| ATTR_CMN_NAMEDATTRCOUNT	| ATTR_CMN_NAMEDATTRLIST| \
      ATTR_CMN_FLAGS		| ATTR_CMN_USERACCESS) != ATTR_CMN_VALIDMASK)
#error AttributeBlockSize: Missing bits in common mask computation!
#endif
	assert((attrlist->commonattr & ~ATTR_CMN_VALIDMASK) == 0);

#if ((ATTR_VOL_FSTYPE		| ATTR_VOL_SIGNATURE		| ATTR_VOL_SIZE				| ATTR_VOL_SPACEFREE 	| \
      ATTR_VOL_SPACEAVAIL	| ATTR_VOL_MINALLOCATION	| ATTR_VOL_ALLOCATIONCLUMP	| ATTR_VOL_IOBLOCKSIZE	| \
      ATTR_VOL_OBJCOUNT		| ATTR_VOL_FILECOUNT		| ATTR_VOL_DIRCOUNT			| ATTR_VOL_MAXOBJCOUNT	| \
      ATTR_VOL_MOUNTPOINT	| ATTR_VOL_NAME				| ATTR_VOL_MOUNTFLAGS		| ATTR_VOL_INFO 		| \
      ATTR_VOL_MOUNTEDDEVICE| ATTR_VOL_ENCODINGSUSED	| ATTR_VOL_CAPABILITIES		| ATTR_VOL_ATTRIBUTES) != ATTR_VOL_VALIDMASK)
#error AttributeBlockSize: Missing bits in volume mask computation!
#endif
	assert((attrlist->volattr & ~ATTR_VOL_VALIDMASK) == 0);

#if ((ATTR_DIR_LINKCOUNT | ATTR_DIR_ENTRYCOUNT | ATTR_DIR_MOUNTSTATUS) != ATTR_DIR_VALIDMASK)
#error AttributeBlockSize: Missing bits in directory mask computation!
#endif
	assert((attrlist->dirattr & ~ATTR_DIR_VALIDMASK) == 0);
#if ((ATTR_FILE_LINKCOUNT	| ATTR_FILE_TOTALSIZE		| ATTR_FILE_ALLOCSIZE 		| ATTR_FILE_IOBLOCKSIZE 	| \
      ATTR_FILE_CLUMPSIZE	| ATTR_FILE_DEVTYPE			| ATTR_FILE_FILETYPE		| ATTR_FILE_FORKCOUNT		| \
      ATTR_FILE_FORKLIST	| ATTR_FILE_DATALENGTH		| ATTR_FILE_DATAALLOCSIZE	| ATTR_FILE_DATAEXTENTS		| \
      ATTR_FILE_RSRCLENGTH	| ATTR_FILE_RSRCALLOCSIZE	| ATTR_FILE_RSRCEXTENTS) != ATTR_FILE_VALIDMASK)
#error AttributeBlockSize: Missing bits in file mask computation!
#endif
	assert((attrlist->fileattr & ~ATTR_FILE_VALIDMASK) == 0);

#if ((ATTR_FORK_TOTALSIZE | ATTR_FORK_ALLOCSIZE) != ATTR_FORK_VALIDMASK)
#error AttributeBlockSize: Missing bits in fork mask computation!
#endif
	assert((attrlist->forkattr & ~ATTR_FORK_VALIDMASK) == 0);

	size = 0;
	
	if ((a = attrlist->commonattr) != 0) {
        if (a & ATTR_CMN_NAME) size += sizeof(struct attrreference);
		if (a & ATTR_CMN_DEVID) size += sizeof(dev_t);
		if (a & ATTR_CMN_FSID) size += sizeof(fsid_t);
		if (a & ATTR_CMN_OBJTYPE) size += sizeof(fsobj_type_t);
		if (a & ATTR_CMN_OBJTAG) size += sizeof(fsobj_tag_t);
		if (a & ATTR_CMN_OBJID) size += sizeof(fsobj_id_t);
        if (a & ATTR_CMN_OBJPERMANENTID) size += sizeof(fsobj_id_t);
		if (a & ATTR_CMN_PAROBJID) size += sizeof(fsobj_id_t);
		if (a & ATTR_CMN_SCRIPT) size += sizeof(text_encoding_t);
		if (a & ATTR_CMN_CRTIME) {
            if (is_64_bit) 
                size += sizeof(struct user_timespec);
            else 
                size += sizeof(struct timespec);
		}
		if (a & ATTR_CMN_MODTIME) {
            if (is_64_bit) 
                size += sizeof(struct user_timespec);
            else 
                size += sizeof(struct timespec);
		}
		if (a & ATTR_CMN_CHGTIME) {
            if (is_64_bit) 
                size += sizeof(struct user_timespec);
            else 
                size += sizeof(struct timespec);
		}
		if (a & ATTR_CMN_ACCTIME) {
            if (is_64_bit) 
                size += sizeof(struct user_timespec);
            else 
                size += sizeof(struct timespec);
		}
		if (a & ATTR_CMN_BKUPTIME) {
            if (is_64_bit) 
                size += sizeof(struct user_timespec);
            else 
                size += sizeof(struct timespec);
		}
		if (a & ATTR_CMN_FNDRINFO) size += 32 * sizeof(u_int8_t);
		if (a & ATTR_CMN_OWNERID) size += sizeof(uid_t);
		if (a & ATTR_CMN_GRPID) size += sizeof(gid_t);
		if (a & ATTR_CMN_ACCESSMASK) size += sizeof(uint32_t);
		if (a & ATTR_CMN_NAMEDATTRCOUNT) size += sizeof(uint32_t);
		if (a & ATTR_CMN_NAMEDATTRLIST) size += sizeof(struct attrreference);
		if (a & ATTR_CMN_FLAGS) size += sizeof(uint32_t);
		if (a & ATTR_CMN_USERACCESS) size += sizeof(uint32_t);
	};
	if ((a = attrlist->volattr) != 0) {
		if (a & ATTR_VOL_FSTYPE) size += sizeof(uint32_t);
		if (a & ATTR_VOL_SIGNATURE) size += sizeof(uint32_t);
		if (a & ATTR_VOL_SIZE) size += sizeof(off_t);
		if (a & ATTR_VOL_SPACEFREE) size += sizeof(off_t);
		if (a & ATTR_VOL_SPACEAVAIL) size += sizeof(off_t);
		if (a & ATTR_VOL_MINALLOCATION) size += sizeof(off_t);
		if (a & ATTR_VOL_ALLOCATIONCLUMP) size += sizeof(off_t);
		if (a & ATTR_VOL_IOBLOCKSIZE) size += sizeof(uint32_t);
		if (a & ATTR_VOL_OBJCOUNT) size += sizeof(uint32_t);
		if (a & ATTR_VOL_FILECOUNT) size += sizeof(uint32_t);
		if (a & ATTR_VOL_DIRCOUNT) size += sizeof(uint32_t);
		if (a & ATTR_VOL_MAXOBJCOUNT) size += sizeof(uint32_t);
		if (a & ATTR_VOL_MOUNTPOINT) size += sizeof(struct attrreference);
        if (a & ATTR_VOL_NAME) size += sizeof(struct attrreference);
		if (a & ATTR_VOL_MOUNTFLAGS) size += sizeof(uint32_t);
        if (a & ATTR_VOL_MOUNTEDDEVICE) size += sizeof(struct attrreference);
        if (a & ATTR_VOL_ENCODINGSUSED) size += sizeof(unsigned long long);
        if (a & ATTR_VOL_CAPABILITIES) size += sizeof(vol_capabilities_attr_t);
        if (a & ATTR_VOL_ATTRIBUTES) size += sizeof(vol_attributes_attr_t);
	};
	if ((a = attrlist->dirattr) != 0) {
		if (a & ATTR_DIR_LINKCOUNT) size += sizeof(uint32_t);
		if (a & ATTR_DIR_ENTRYCOUNT) size += sizeof(uint32_t);
		if (a & ATTR_DIR_MOUNTSTATUS) size += sizeof(uint32_t);
	};
	if ((a = attrlist->fileattr) != 0) {
		if (a & ATTR_FILE_LINKCOUNT) size += sizeof(uint32_t);
		if (a & ATTR_FILE_TOTALSIZE) size += sizeof(off_t);
		if (a & ATTR_FILE_ALLOCSIZE) size += sizeof(off_t);
		if (a & ATTR_FILE_IOBLOCKSIZE) size += sizeof(uint32_t);
		if (a & ATTR_FILE_CLUMPSIZE) size += sizeof(uint32_t);
		if (a & ATTR_FILE_DEVTYPE) size += sizeof(uint32_t);
		if (a & ATTR_FILE_FILETYPE) size += sizeof(uint32_t);
		if (a & ATTR_FILE_FORKCOUNT) size += sizeof(uint32_t);
		if (a & ATTR_FILE_FORKLIST) size += sizeof(struct attrreference);
		if (a & ATTR_FILE_DATALENGTH) size += sizeof(off_t);
		if (a & ATTR_FILE_DATAALLOCSIZE) size += sizeof(off_t);
		if (a & ATTR_FILE_DATAEXTENTS) size += sizeof(extentrecord);
		if (a & ATTR_FILE_RSRCLENGTH) size += sizeof(off_t);
		if (a & ATTR_FILE_RSRCALLOCSIZE) size += sizeof(off_t);
		if (a & ATTR_FILE_RSRCEXTENTS) size += sizeof(extentrecord);
	};
	if ((a = attrlist->forkattr) != 0) {
		if (a & ATTR_FORK_TOTALSIZE) size += sizeof(off_t);
		if (a & ATTR_FORK_ALLOCSIZE) size += sizeof(off_t);
	};

    return size;
}



static void
packvolattr (struct attrlist *alist,
			 struct iso_node *ip,	/* ip for root directory */
			 void **attrbufptrptr,
			 void **varbufptrptr)
{
    void *attrbufptr;
    void *varbufptr;
	struct iso_mnt *imp;
	struct mount *mp;
	attrgroup_t a;
	uint32_t attrlength;
	boolean_t is_64_bit = proc_is64bit(current_proc());
	
	attrbufptr = *attrbufptrptr;
	varbufptr = *varbufptrptr;
	imp = ip->i_mnt;
	mp = imp->im_mountp;

    if ((a = alist->commonattr) != 0) {
        if (a & ATTR_CMN_NAME) {
            attrlength = strlen( imp->volume_id ) + 1;
            ((struct attrreference *)attrbufptr)->attr_dataoffset = (u_int8_t *)varbufptr - (u_int8_t *)attrbufptr;
            ((struct attrreference *)attrbufptr)->attr_length = attrlength;
            (void) strncpy((unsigned char *)varbufptr, imp->volume_id, attrlength);

            /* Advance beyond the space just allocated and round up to the next 4-byte boundary: */
            (u_int8_t *)varbufptr += attrlength + ((4 - (attrlength & 3)) & 3);
            ++((struct attrreference *)attrbufptr);
        };
		if (a & ATTR_CMN_DEVID) *((dev_t *)attrbufptr)++ = vnode_specrdev(imp->im_devvp);
		if (a & ATTR_CMN_FSID) *((fsid_t *)attrbufptr)++ = vfs_statfs(vnode_mount(ITOV(ip)))->f_fsid;
		if (a & ATTR_CMN_OBJTYPE) *((fsobj_type_t *)attrbufptr)++ = 0;
		if (a & ATTR_CMN_OBJTAG) *((fsobj_tag_t *)attrbufptr)++ = VT_ISOFS;
		if (a & ATTR_CMN_OBJID)	{
			((fsobj_id_t *)attrbufptr)->fid_objno = 0;
			((fsobj_id_t *)attrbufptr)->fid_generation = 0;
			++((fsobj_id_t *)attrbufptr);
		};
        if (a & ATTR_CMN_OBJPERMANENTID) {
            ((fsobj_id_t *)attrbufptr)->fid_objno = 0;
            ((fsobj_id_t *)attrbufptr)->fid_generation = 0;
            ++((fsobj_id_t *)attrbufptr);
        };
		if (a & ATTR_CMN_PAROBJID) {
            ((fsobj_id_t *)attrbufptr)->fid_objno = 0;
			((fsobj_id_t *)attrbufptr)->fid_generation = 0;
			++((fsobj_id_t *)attrbufptr);
		};
        if (a & ATTR_CMN_SCRIPT) *((text_encoding_t *)attrbufptr)++ = 0;
		if (a & ATTR_CMN_CRTIME) {
		    if (is_64_bit) {
		        struct user_timespec *tmpp = ((struct user_timespec *)attrbufptr)++;
		        tmpp->tv_sec = (user_time_t) imp->creation_date.tv_sec;
		        tmpp->tv_nsec = imp->creation_date.tv_nsec;
		    }
		    else {
		        *((struct timespec *)attrbufptr)++ = imp->creation_date;
		    }
		}
		if (a & ATTR_CMN_MODTIME) {
		    if (is_64_bit) {
		        struct user_timespec *tmpp = ((struct user_timespec *)attrbufptr)++;
		        tmpp->tv_sec = (user_time_t) imp->modification_date.tv_sec;
		        tmpp->tv_nsec = imp->modification_date.tv_nsec;
		    }
		    else {
		        *((struct timespec *)attrbufptr)++ = imp->modification_date;
		    }
		}
		if (a & ATTR_CMN_CHGTIME) {
		    if (is_64_bit) {
		        struct user_timespec *tmpp = ((struct user_timespec *)attrbufptr)++;
		        tmpp->tv_sec = (user_time_t) imp->modification_date.tv_sec;
		        tmpp->tv_nsec = imp->modification_date.tv_nsec;
		    }
		    else {
		        *((struct timespec *)attrbufptr)++ = imp->modification_date;
		    }
		}
		if (a & ATTR_CMN_ACCTIME) {
		    if (is_64_bit) {
		        struct user_timespec *tmpp = ((struct user_timespec *)attrbufptr)++;
		        tmpp->tv_sec = (user_time_t) imp->modification_date.tv_sec;
		        tmpp->tv_nsec = imp->modification_date.tv_nsec;
		    }
		    else {
		        *((struct timespec *)attrbufptr)++ = imp->modification_date;
		    }
		}
		if (a & ATTR_CMN_BKUPTIME) {
			((struct timespec *)attrbufptr)->tv_sec = 0;
			((struct timespec *)attrbufptr)->tv_nsec = 0;
			++((struct timespec *)attrbufptr);
		};
		if (a & ATTR_CMN_FNDRINFO) {
            bzero (attrbufptr, 32 * sizeof(u_int8_t));
            (u_int8_t *)attrbufptr += 32 * sizeof(u_int8_t);
		};
		if (a & ATTR_CMN_OWNERID) *((uid_t *)attrbufptr)++ = ip->inode.iso_uid;
		if (a & ATTR_CMN_GRPID) *((gid_t *)attrbufptr)++ = ip->inode.iso_gid;
		if (a & ATTR_CMN_ACCESSMASK) *((uint32_t *)attrbufptr)++ = (uint32_t)ip->inode.iso_mode;
		if (a & ATTR_CMN_FLAGS) *((uint32_t *)attrbufptr)++ = 0;
		if (a & ATTR_CMN_USERACCESS) {
			*((uint32_t *)attrbufptr)++ =
				DerivePermissionSummary(ip->inode.iso_uid,
										ip->inode.iso_gid,
										ip->inode.iso_mode,
										imp);
		};
	};
	
	if ((a = alist->volattr) != 0) {
		off_t blocksize = (off_t)imp->logical_block_size;

		if (a & ATTR_VOL_FSTYPE) *((uint32_t *)attrbufptr)++ = (uint32_t)vfs_typenum(mp);
		if (a & ATTR_VOL_SIGNATURE) *((uint32_t *)attrbufptr)++ = (uint32_t)ISO9660SIGNATURE;
        if (a & ATTR_VOL_SIZE) *((off_t *)attrbufptr)++ = (off_t)imp->volume_space_size * blocksize;
        if (a & ATTR_VOL_SPACEFREE) *((off_t *)attrbufptr)++ = 0;
        if (a & ATTR_VOL_SPACEAVAIL) *((off_t *)attrbufptr)++ = 0;
        if (a & ATTR_VOL_MINALLOCATION) *((off_t *)attrbufptr)++ = blocksize;
		if (a & ATTR_VOL_ALLOCATIONCLUMP) *((off_t *)attrbufptr)++ = blocksize;
        if (a & ATTR_VOL_IOBLOCKSIZE) *((uint32_t *)attrbufptr)++ = (uint32_t)blocksize;
		if (a & ATTR_VOL_OBJCOUNT) *((uint32_t *)attrbufptr)++ = 0;
		if (a & ATTR_VOL_FILECOUNT) *((uint32_t *)attrbufptr)++ = 0;
		if (a & ATTR_VOL_DIRCOUNT) *((uint32_t *)attrbufptr)++ = 0;
		if (a & ATTR_VOL_MAXOBJCOUNT) *((uint32_t *)attrbufptr)++ = 0xFFFFFFFF;
        if (a & ATTR_VOL_NAME) {
            attrlength = strlen( imp->volume_id ) + 1;
            ((struct attrreference *)attrbufptr)->attr_dataoffset = (u_int8_t *)varbufptr - (u_int8_t *)attrbufptr;
            ((struct attrreference *)attrbufptr)->attr_length = attrlength;
            (void) strncpy((unsigned char *)varbufptr, imp->volume_id, attrlength);

            /* Advance beyond the space just allocated and round up to the next 4-byte boundary: */
            (u_int8_t *)varbufptr += attrlength + ((4 - (attrlength & 3)) & 3);
            ++((struct attrreference *)attrbufptr);
        };
		if (a & ATTR_VOL_MOUNTFLAGS) {
		    *((uint32_t *)attrbufptr)++ = (uint32_t)vfs_flags(mp);
		}
        if (a & ATTR_VOL_MOUNTEDDEVICE) {
            ((struct attrreference *)attrbufptr)->attr_dataoffset = (u_int8_t *)varbufptr - (u_int8_t *)attrbufptr;
            ((struct attrreference *)attrbufptr)->attr_length = strlen(vfs_statfs(mp)->f_mntfromname) + 1;
			attrlength = ((struct attrreference *)attrbufptr)->attr_length;
			attrlength = attrlength + ((4 - (attrlength & 3)) & 3);		/* round up to the next 4-byte boundary: */
			(void) bcopy(vfs_statfs(mp)->f_mntfromname, varbufptr, attrlength);
			
			/* Advance beyond the space just allocated: */
            (u_int8_t *)varbufptr += attrlength;
            ++((struct attrreference *)attrbufptr);
        };
        if (a & ATTR_VOL_ENCODINGSUSED) *((unsigned long long *)attrbufptr)++ = (unsigned long long)0;
        if (a & ATTR_VOL_CAPABILITIES) {
        	((vol_capabilities_attr_t *)attrbufptr)->capabilities[VOL_CAPABILITIES_FORMAT] =
        			(imp->iso_ftype == ISO_FTYPE_RRIP ? VOL_CAP_FMT_SYMBOLICLINKS : 0) |
        			(imp->iso_ftype == ISO_FTYPE_RRIP ? VOL_CAP_FMT_HARDLINKS : 0) |
        			(imp->iso_ftype == ISO_FTYPE_RRIP || imp->iso_ftype == ISO_FTYPE_JOLIET
        				? VOL_CAP_FMT_CASE_SENSITIVE : 0) |
					VOL_CAP_FMT_CASE_PRESERVING |
        			VOL_CAP_FMT_FAST_STATFS;
        	((vol_capabilities_attr_t *)attrbufptr)->capabilities[VOL_CAPABILITIES_INTERFACES] =
        			VOL_CAP_INT_ATTRLIST |
        			VOL_CAP_INT_NFSEXPORT;
        	((vol_capabilities_attr_t *)attrbufptr)->capabilities[VOL_CAPABILITIES_RESERVED1] = 0;
        	((vol_capabilities_attr_t *)attrbufptr)->capabilities[VOL_CAPABILITIES_RESERVED2] = 0;

        	((vol_capabilities_attr_t *)attrbufptr)->valid[VOL_CAPABILITIES_FORMAT] =
        			VOL_CAP_FMT_PERSISTENTOBJECTIDS |
        			VOL_CAP_FMT_SYMBOLICLINKS |
        			VOL_CAP_FMT_HARDLINKS |
					VOL_CAP_FMT_JOURNAL |
					VOL_CAP_FMT_JOURNAL_ACTIVE |
					VOL_CAP_FMT_NO_ROOT_TIMES |
					VOL_CAP_FMT_SPARSE_FILES |
					VOL_CAP_FMT_ZERO_RUNS |
					VOL_CAP_FMT_CASE_SENSITIVE |
					VOL_CAP_FMT_CASE_PRESERVING |
					VOL_CAP_FMT_FAST_STATFS | 
					VOL_CAP_FMT_2TB_FILESIZE;
        	((vol_capabilities_attr_t *)attrbufptr)->valid[VOL_CAPABILITIES_INTERFACES] =
        			VOL_CAP_INT_SEARCHFS |
        			VOL_CAP_INT_ATTRLIST |
        			VOL_CAP_INT_NFSEXPORT |
					VOL_CAP_INT_READDIRATTR |
					VOL_CAP_INT_EXCHANGEDATA |
					VOL_CAP_INT_COPYFILE |
					VOL_CAP_INT_ALLOCATE |
					VOL_CAP_INT_VOL_RENAME |
					VOL_CAP_INT_ADVLOCK |
					VOL_CAP_INT_FLOCK;
        	((vol_capabilities_attr_t *)attrbufptr)->valid[VOL_CAPABILITIES_RESERVED1] = 0;
        	((vol_capabilities_attr_t *)attrbufptr)->valid[VOL_CAPABILITIES_RESERVED2] = 0;

            ++((vol_capabilities_attr_t *)attrbufptr);
        };
        if (a & ATTR_VOL_ATTRIBUTES) {
        	((vol_attributes_attr_t *)attrbufptr)->validattr.commonattr = ATTR_CMN_VALIDMASK;
        	((vol_attributes_attr_t *)attrbufptr)->validattr.volattr = ATTR_VOL_VALIDMASK;
        	((vol_attributes_attr_t *)attrbufptr)->validattr.dirattr = ATTR_DIR_VALIDMASK;
        	((vol_attributes_attr_t *)attrbufptr)->validattr.fileattr = ATTR_FILE_VALIDMASK;
        	((vol_attributes_attr_t *)attrbufptr)->validattr.forkattr = ATTR_FORK_VALIDMASK;

        	((vol_attributes_attr_t *)attrbufptr)->nativeattr.commonattr = ATTR_CMN_VALIDMASK;
        	((vol_attributes_attr_t *)attrbufptr)->nativeattr.volattr = ATTR_VOL_VALIDMASK;
        	((vol_attributes_attr_t *)attrbufptr)->nativeattr.dirattr = ATTR_DIR_VALIDMASK;
        	((vol_attributes_attr_t *)attrbufptr)->nativeattr.fileattr = ATTR_FILE_VALIDMASK;
        	((vol_attributes_attr_t *)attrbufptr)->nativeattr.forkattr = ATTR_FORK_VALIDMASK;

            ++((vol_attributes_attr_t *)attrbufptr);
        };
	};

	*attrbufptrptr = attrbufptr;
	*varbufptrptr = varbufptr;
}


void
packcommonattr (struct attrlist *alist,
				struct iso_node *ip,
				void **attrbufptrptr,
				void **varbufptrptr)
{
	void *attrbufptr;
	void *varbufptr;
	attrgroup_t a;
	uint32_t attrlength;
	boolean_t is_64_bit = proc_is64bit(current_proc());
	
	attrbufptr = *attrbufptrptr;
	varbufptr = *varbufptrptr;
	
    if ((a = alist->commonattr) != 0) {
		struct iso_mnt *imp = ip->i_mnt;

        if (a & ATTR_CMN_NAME) {
			/* special case root since we know how to get it's name */
			if (vnode_isvroot(ITOV(ip))) {
				attrlength = strlen( imp->volume_id ) + 1;
				(void) strncpy((unsigned char *)varbufptr, imp->volume_id, attrlength);
        	} else {
            	attrlength = strlen(ip->i_namep) + 1;
				(void) strncpy((unsigned char *)varbufptr, ip->i_namep, attrlength);
            }

			((struct attrreference *)attrbufptr)->attr_dataoffset = (u_int8_t *)varbufptr - (u_int8_t *)attrbufptr;
			((struct attrreference *)attrbufptr)->attr_length = attrlength;
            /* Advance beyond the space just allocated and round up to the next 4-byte boundary: */
            (u_int8_t *)varbufptr += attrlength + ((4 - (attrlength & 3)) & 3);
            ++((struct attrreference *)attrbufptr);
        };
		if (a & ATTR_CMN_DEVID) *((dev_t *)attrbufptr)++ = ip->i_dev;
		if (a & ATTR_CMN_FSID) *((fsid_t *)attrbufptr)++ = vfs_statfs(vnode_mount(ITOV(ip)))->f_fsid;
		if (a & ATTR_CMN_OBJTYPE) *((fsobj_type_t *)attrbufptr)++ = vnode_vtype(ITOV(ip));
		if (a & ATTR_CMN_OBJTAG) *((fsobj_tag_t *)attrbufptr)++ = vnode_tag(ITOV(ip));
        if (a & ATTR_CMN_OBJID)	{
			if (vnode_isvroot(ITOV(ip)))
				((fsobj_id_t *)attrbufptr)->fid_objno = 2;	/* force root to be 2 */
			else
            	((fsobj_id_t *)attrbufptr)->fid_objno = ip->i_number;
			((fsobj_id_t *)attrbufptr)->fid_generation = 0;
			++((fsobj_id_t *)attrbufptr);
		};
        if (a & ATTR_CMN_OBJPERMANENTID)	{
			if (vnode_isvroot(ITOV(ip)))
				((fsobj_id_t *)attrbufptr)->fid_objno = 2;	/* force root to be 2 */
			else
            	((fsobj_id_t *)attrbufptr)->fid_objno = ip->i_number;
            ((fsobj_id_t *)attrbufptr)->fid_generation = 0;
            ++((fsobj_id_t *)attrbufptr);
        };
		if (a & ATTR_CMN_PAROBJID) {
			struct iso_directory_record *dp = (struct iso_directory_record *)imp->root;
			ino_t rootino = isodirino(dp, imp);

			if (ip->i_number == rootino)
				((fsobj_id_t *)attrbufptr)->fid_objno = 1;	/* force root parent to be 1 */
			else if (ip->i_parent == rootino)
				((fsobj_id_t *)attrbufptr)->fid_objno = 2;	/* force root to be 2 */
			else
            	((fsobj_id_t *)attrbufptr)->fid_objno = ip->i_parent;
			((fsobj_id_t *)attrbufptr)->fid_generation = 0;
			++((fsobj_id_t *)attrbufptr);
		};
        if (a & ATTR_CMN_SCRIPT) *((text_encoding_t *)attrbufptr)++ = 0;
		if (a & ATTR_CMN_CRTIME) {
		    if (is_64_bit) {
		        struct user_timespec *tmpp = ((struct user_timespec *)attrbufptr)++;
		        tmpp->tv_sec = (user_time_t) ip->inode.iso_mtime.tv_sec;
		        tmpp->tv_nsec = ip->inode.iso_mtime.tv_nsec;
		    }
		    else {
                *((struct timespec *)attrbufptr)++ = ip->inode.iso_mtime;
		    }
		}
		if (a & ATTR_CMN_MODTIME) {
		    if (is_64_bit) {
		        struct user_timespec *tmpp = ((struct user_timespec *)attrbufptr)++;
		        tmpp->tv_sec = (user_time_t) ip->inode.iso_mtime.tv_sec;
		        tmpp->tv_nsec = ip->inode.iso_mtime.tv_nsec;
		    }
		    else {
                *((struct timespec *)attrbufptr)++ = ip->inode.iso_mtime;
		    }
		}
		if (a & ATTR_CMN_CHGTIME) {
		    if (is_64_bit) {
		        struct user_timespec *tmpp = ((struct user_timespec *)attrbufptr)++;
		        tmpp->tv_sec = (user_time_t) ip->inode.iso_ctime.tv_sec;
		        tmpp->tv_nsec = ip->inode.iso_ctime.tv_nsec;
		    }
		    else {
                *((struct timespec *)attrbufptr)++ = ip->inode.iso_ctime;
		    }
		}
		if (a & ATTR_CMN_ACCTIME) {
		    if (is_64_bit) {
		        struct user_timespec *tmpp = ((struct user_timespec *)attrbufptr)++;
		        tmpp->tv_sec = (user_time_t) ip->inode.iso_atime.tv_sec;
		        tmpp->tv_nsec = ip->inode.iso_atime.tv_nsec;
		    }
		    else {
                *((struct timespec *)attrbufptr)++ = ip->inode.iso_atime;
		    }
		}
		if (a & ATTR_CMN_BKUPTIME) {
		    if (is_64_bit) {
		        struct user_timespec *tmpp = ((struct user_timespec *)attrbufptr)++;
		        tmpp->tv_sec = (user_time_t) 0;
		        tmpp->tv_nsec = 0;
		    }
		    else {
                ((struct timespec *)attrbufptr)->tv_sec = 0;
                ((struct timespec *)attrbufptr)->tv_nsec = 0;
                ++((struct timespec *)attrbufptr);
                    *((struct timespec *)attrbufptr)++ = ip->inode.iso_atime;
		    }
		}
		if (a & ATTR_CMN_FNDRINFO) {
			struct finder_info finfo;

			bzero(&finfo, sizeof(finfo));
			finfo.fdFlags = ip->i_FinderFlags;
			finfo.fdLocation.v = -1;
			finfo.fdLocation.h = -1;
			if (vnode_isreg(ITOV(ip))) {
				finfo.fdType = ip->i_FileType;
				finfo.fdCreator = ip->i_Creator;
			}
            bcopy (&finfo, attrbufptr, sizeof(finfo));
            (u_int8_t *)attrbufptr += sizeof(finfo);
            bzero (attrbufptr, EXTFNDRINFOSIZE);
            (u_int8_t *)attrbufptr += EXTFNDRINFOSIZE;
		};
		if (a & ATTR_CMN_OWNERID) *((uid_t *)attrbufptr)++ = ip->inode.iso_uid;
		if (a & ATTR_CMN_GRPID) *((gid_t *)attrbufptr)++ = ip->inode.iso_gid;
		if (a & ATTR_CMN_ACCESSMASK) *((uint32_t *)attrbufptr)++ = (uint32_t)ip->inode.iso_mode;
		if (a & ATTR_CMN_FLAGS) *((uint32_t *)attrbufptr)++ = 0; /* could also use ip->i_flag */
		if (a & ATTR_CMN_USERACCESS) {
			*((uint32_t *)attrbufptr)++ =
				DerivePermissionSummary(ip->inode.iso_uid,
										ip->inode.iso_gid,
										ip->inode.iso_mode,
										imp);
		};
	};
	
	*attrbufptrptr = attrbufptr;
	*varbufptrptr = varbufptr;
}


void
packdirattr(struct attrlist *alist,
			struct iso_node *ip,
			void **attrbufptrptr,
			__unused void **varbufptrptr)
{
    void *attrbufptr;
    attrgroup_t a;
	int filcnt, dircnt;
	
	attrbufptr = *attrbufptrptr;
	filcnt = dircnt = 0;
	
	a = alist->dirattr;
	if (vnode_isdir(ITOV(ip)) && (a != 0)) {
		/*
		 * if we haven't counted our children yet, do it now...
		 */
		if ((ip->i_entries == 0) &&
		    (a & (ATTR_DIR_LINKCOUNT | ATTR_DIR_ENTRYCOUNT))) {
			(void) isochildcount(ITOV(ip), &dircnt, &filcnt);

			if ((ip->inode.iso_links == 1) && (dircnt != 0))
				ip->inode.iso_links = dircnt;
			if ((filcnt + dircnt) > 0)
				ip->i_entries = dircnt + filcnt;
		}

		if (a & ATTR_DIR_LINKCOUNT) {
			*((uint32_t *)attrbufptr)++ = ip->inode.iso_links;
		}
		if (a & ATTR_DIR_ENTRYCOUNT) {
			/* exclude '.' and '..' from total caount */
			*((uint32_t *)attrbufptr)++ = ((ip->i_entries <= 2) ? 0 : (ip->i_entries - 2));
		}
		if (a & ATTR_DIR_MOUNTSTATUS) {
			if (vnode_mountedhere(ITOV(ip))) {
				*((uint32_t *)attrbufptr)++ = DIR_MNTSTATUS_MNTPOINT;
			} else {
				*((uint32_t *)attrbufptr)++ = 0;
			};
		};
	};
	
	*attrbufptrptr = attrbufptr;
}


void
packfileattr(struct attrlist *alist,
			 struct iso_node *ip,
			 void **attrbufptrptr,
			 void **varbufptrptr)
{
    void *attrbufptr = *attrbufptrptr;
    void *varbufptr = *varbufptrptr;
    attrgroup_t a = alist->fileattr;
	
	if (vnode_isreg(ITOV(ip)) && (a != 0)) {
		if (a & ATTR_FILE_LINKCOUNT)
			*((uint32_t *)attrbufptr)++ = ip->inode.iso_links;
		if (a & ATTR_FILE_TOTALSIZE)
			*((off_t *)attrbufptr)++ = (off_t)ip->i_size;
		if (a & ATTR_FILE_ALLOCSIZE)
			*((off_t *)attrbufptr)++ = (off_t)ip->i_size;
		if (a & ATTR_FILE_IOBLOCKSIZE)
			*((uint32_t *)attrbufptr)++ = ip->i_mnt->logical_block_size;
		if (a & ATTR_FILE_CLUMPSIZE)
			*((uint32_t *)attrbufptr)++ = ip->i_mnt->logical_block_size;
		if (a & ATTR_FILE_DEVTYPE)
			*((uint32_t *)attrbufptr)++ = (uint32_t)ip->inode.iso_rdev;
		if (a & ATTR_FILE_DATALENGTH)
			*((off_t *)attrbufptr)++ = (off_t)ip->i_size;
		if (a & ATTR_FILE_DATAALLOCSIZE)
			*((off_t *)attrbufptr)++ = (off_t)ip->i_size;
		if (a & ATTR_FILE_RSRCLENGTH)
			*((off_t *)attrbufptr)++ = (off_t)ip->i_rsrcsize;
		if (a & ATTR_FILE_RSRCALLOCSIZE)
			*((off_t *)attrbufptr)++ = (off_t)ip->i_rsrcsize;
	}
	
	*attrbufptrptr = attrbufptr;
	*varbufptrptr = varbufptr;
}


void
packattrblk(struct attrlist *alist,
			struct vnode *vp,
			void **attrbufptrptr,
			void **varbufptrptr)
{
	struct iso_node *ip = VTOI(vp);

	if (alist->volattr != 0) {
		packvolattr(alist, ip, attrbufptrptr, varbufptrptr);
	} else {
		packcommonattr(alist, ip, attrbufptrptr, varbufptrptr);
		
		switch (vnode_vtype(ITOV(ip))) {
		  case VDIR:
			packdirattr(alist, ip, attrbufptrptr, varbufptrptr);
			break;
			
		  case VREG:
			packfileattr(alist, ip, attrbufptrptr, varbufptrptr);
			break;
		  
		  /* Without this the compiler complains about VNON,VBLK,VCHR,VLNK,VSOCK,VFIFO,VBAD and VSTR
		     not being handled...
		   */
		  default:
			break;
		};
	};
};
