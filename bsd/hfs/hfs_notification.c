/*
 * Copyright (C) 2003, 2005 Apple Computer, Inc. All rights reserved.
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

#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/file.h>
#include <sys/dirent.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/mount_internal.h>
#include <sys/vnode.h>
#include <sys/vnode_internal.h>
#include <sys/malloc.h>
#include <sys/ubc.h>
#include <sys/quota.h>

#include <sys/kdebug.h>

#include "hfs.h"
#include "hfs_catalog.h"
#include "hfs_cnode.h"
#include "hfs_dbg.h"
#include "hfs_mount.h"
#include "hfs_quota.h"
#include "hfs_endian.h"

#include "hfscommon/headers/BTreesInternal.h"
#include "hfscommon/headers/FileMgrInternal.h"



void hfs_generate_volume_notifications(struct hfsmount *hfsmp) 
{
	fsid_t fsid;
	u_int32_t freeblks, state=999;
		
	fsid.val[0] = (long)hfsmp->hfs_raw_dev;
	fsid.val[1] = (long)vfs_typenum(HFSTOVFS(hfsmp));
	
	freeblks = hfs_freeblks(hfsmp, 1);

	if (freeblks < hfsmp->hfs_freespace_notify_dangerlimit) {
		state = 2;
	} else if (freeblks < hfsmp->hfs_freespace_notify_warninglimit) {
		state = 1;
	} else if (freeblks >= hfsmp->hfs_freespace_notify_desiredlevel) {
		state = 0;
	}

	if (state == 2 && !(hfsmp->hfs_notification_conditions & VQ_VERYLOWDISK)) {
		/* Dump some logging to track down intermittent issues */
		printf("HFS: Very Low Disk: freeblks: %d, dangerlimit: %d\n", freeblks, hfsmp->hfs_freespace_notify_dangerlimit);
#if HFS_SPARSE_DEV
		if (hfsmp->hfs_flags & HFS_HAS_SPARSE_DEVICE) {
			if (hfsmp->hfs_backingfs_rootvp) {
				struct mount *mp = vnode_mount (hfsmp->hfs_backingfs_rootvp);
				/* If we're a sparse device, dump some info about the backing store... */
				if (mp) {
					printf("HFS: Very Low Disk: backingstore b_avail %lld, tag %d\n", mp->mnt_vfsstat.f_bavail, hfsmp->hfs_backingfs_rootvp->v_tag);
				}
			}
		}
#endif
		hfsmp->hfs_notification_conditions |= (VQ_VERYLOWDISK|VQ_LOWDISK);
		vfs_event_signal(&fsid, hfsmp->hfs_notification_conditions, (intptr_t)NULL);
	} else if (state == 1) {
		if (!(hfsmp->hfs_notification_conditions & VQ_LOWDISK)) {
			printf("HFS: Low Disk: freeblks: %d, warninglimit: %d\n", freeblks, hfsmp->hfs_freespace_notify_warninglimit);
			hfsmp->hfs_notification_conditions |= VQ_LOWDISK;
			vfs_event_signal(&fsid, hfsmp->hfs_notification_conditions, (intptr_t)NULL);
		} else if (hfsmp->hfs_notification_conditions & VQ_VERYLOWDISK) {
			hfsmp->hfs_notification_conditions &= ~VQ_VERYLOWDISK;
			vfs_event_signal(&fsid, hfsmp->hfs_notification_conditions, (intptr_t)NULL);
		}
	} else if (state == 0) {
		if (hfsmp->hfs_notification_conditions & (VQ_LOWDISK|VQ_VERYLOWDISK)) {
			hfsmp->hfs_notification_conditions &= ~(VQ_VERYLOWDISK|VQ_LOWDISK);
			if (hfsmp->hfs_notification_conditions == 0) {
				vfs_event_signal(&fsid, VQ_UPDATE, (intptr_t)NULL);
			} else {
				vfs_event_signal(&fsid, hfsmp->hfs_notification_conditions, (intptr_t)NULL);
			}
		}
	}
}
