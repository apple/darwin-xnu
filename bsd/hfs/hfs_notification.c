/*
 * Copyright (C) 2003 Apple Computer, Inc. All rights reserved.
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

#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/file.h>
#include <sys/dirent.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/vnode.h>
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



void hfs_generate_volume_notifications(struct hfsmount *hfsmp) {
	ExtendedVCB *vcb = HFSTOVCB(hfsmp);
	fsid_t fsid;
		
	fsid.val[0] = (long)hfsmp->hfs_raw_dev;
	fsid.val[1] = (long)vfs_typenum(HFSTOVFS(hfsmp));
	
	if (hfsmp->hfs_notification_conditions & VQ_LOWDISK) {
		/* Check to see whether the free space is back above the minimal level: */
		if (hfs_freeblks(hfsmp, 1) > hfsmp->hfs_freespace_notify_desiredlevel) {
            hfsmp->hfs_notification_conditions &= ~VQ_LOWDISK;
            vfs_event_signal(&fsid, hfsmp->hfs_notification_conditions, NULL);
		}
	} else {
		/* Check to see whether the free space fell below the requested limit: */
		if (hfs_freeblks(hfsmp, 1) < hfsmp->hfs_freespace_notify_warninglimit) {
            hfsmp->hfs_notification_conditions |= VQ_LOWDISK;
            vfs_event_signal(&fsid, hfsmp->hfs_notification_conditions, NULL);
		}
	};
}
