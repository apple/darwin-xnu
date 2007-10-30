/*
 * Copyright (c) 2002-2007 Apple Inc. All rights reserved.
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
#ifndef _HFS_ATTRLIST_H_
#define _HFS_ATTRLIST_H_

#include <sys/appleapiopts.h>

#ifdef KERNEL
#ifdef __APPLE_API_PRIVATE
#include <sys/attr.h>
#include <sys/vnode.h>

#include <hfs/hfs_catalog.h>
#include <hfs/hfs_cnode.h>


struct attrblock {
	struct attrlist * ab_attrlist;
	void **		  ab_attrbufpp;
	void **		  ab_varbufpp;
	int		  ab_flags;
	int		  ab_blocksize;
	vfs_context_t	  ab_context;
};

/* 
 * The following define the attributes that HFS supports:
 */

#define HFS_ATTR_CMN_VALID				\
	(ATTR_CMN_NAME | ATTR_CMN_DEVID	|		\
	 ATTR_CMN_FSID | ATTR_CMN_OBJTYPE |		\
	 ATTR_CMN_OBJTAG | ATTR_CMN_OBJID |		\
	 ATTR_CMN_OBJPERMANENTID | ATTR_CMN_PAROBJID |	\
	 ATTR_CMN_SCRIPT | ATTR_CMN_CRTIME |		\
	 ATTR_CMN_MODTIME | ATTR_CMN_CHGTIME |		\
	 ATTR_CMN_ACCTIME | ATTR_CMN_BKUPTIME |		\
	 ATTR_CMN_FNDRINFO |ATTR_CMN_OWNERID |		\
	 ATTR_CMN_GRPID | ATTR_CMN_ACCESSMASK |		\
	 ATTR_CMN_FLAGS | ATTR_CMN_USERACCESS |		\
	 ATTR_CMN_EXTENDED_SECURITY | ATTR_CMN_UUID |	\
	 ATTR_CMN_GRPUUID | ATTR_CMN_FILEID |		\
	 ATTR_CMN_PARENTID )

#define HFS_ATTR_DIR_VALID				\
	(ATTR_DIR_LINKCOUNT | ATTR_DIR_ENTRYCOUNT | ATTR_DIR_MOUNTSTATUS)

#define HFS_ATTR_FILE_VALID				  \
	(ATTR_FILE_LINKCOUNT |ATTR_FILE_TOTALSIZE |	  \
	 ATTR_FILE_ALLOCSIZE | ATTR_FILE_IOBLOCKSIZE |	  \
	 ATTR_FILE_CLUMPSIZE | ATTR_FILE_DEVTYPE |	  \
	 ATTR_FILE_FORKCOUNT | ATTR_FILE_FORKLIST |	  \
	 ATTR_FILE_DATALENGTH | ATTR_FILE_DATAALLOCSIZE | \
	 ATTR_FILE_RSRCLENGTH | ATTR_FILE_RSRCALLOCSIZE)


extern int hfs_attrblksize(struct attrlist *attrlist);

extern unsigned long DerivePermissionSummary(uid_t obj_uid, gid_t obj_gid,
			mode_t obj_mode, struct mount *mp,
			kauth_cred_t cred, struct proc *p);

extern void hfs_packattrblk(struct attrblock *abp, struct hfsmount *hfsmp,
		struct vnode *vp, struct cat_desc *descp, struct cat_attr *attrp,
		struct cat_fork *datafork, struct cat_fork *rsrcfork, struct proc *p);

#endif /* __APPLE_API_PRIVATE */
#endif /* KERNEL */
#endif /* ! _HFS_ATTRLIST_H_ */
