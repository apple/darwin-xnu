/*
 * Copyright (c) 2002 Apple Computer, Inc. All rights reserved.
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
};


#define	ATTR_OWNERSHIP_SETMASK	(ATTR_CMN_OWNERID | ATTR_CMN_GRPID | \
	ATTR_CMN_ACCESSMASK | ATTR_CMN_FLAGS | ATTR_CMN_CRTIME |     \
	ATTR_CMN_MODTIME | ATTR_CMN_CHGTIME | ATTR_CMN_ACCTIME)

#define ATTR_DATAFORK_MASK	(ATTR_FILE_TOTALSIZE | \
    ATTR_FILE_DATALENGTH | ATTR_FILE_DATAALLOCSIZE | ATTR_FILE_DATAEXTENTS)

#define ATTR_RSRCFORK_MASK	(ATTR_FILE_TOTALSIZE | \
    ATTR_FILE_RSRCLENGTH | ATTR_FILE_RSRCALLOCSIZE | ATTR_FILE_RSRCEXTENTS)


extern int hfs_attrblksize(struct attrlist *attrlist);

extern unsigned long DerivePermissionSummary(uid_t obj_uid, gid_t obj_gid,
			mode_t obj_mode, struct mount *mp,
			struct ucred *cred, struct proc *p);

extern void hfs_packattrblk(struct attrblock *abp, struct hfsmount *hfsmp,
		struct vnode *vp, struct cat_desc *descp, struct cat_attr *attrp,
		struct cat_fork *datafork, struct cat_fork *rsrcfork, struct proc *p);

#endif /* __APPLE_API_PRIVATE */
#endif /* KERNEL */
#endif /* ! _HFS_ATTRLIST_H_ */
