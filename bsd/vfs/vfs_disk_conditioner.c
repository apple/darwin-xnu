/*
 * Copyright (c) 2016 Apple Computer, Inc. All rights reserved.
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

#include <sys/fsctl.h>
#include <stdbool.h>
#include <sys/time.h>
#include <sys/buf.h>
#include <sys/mount_internal.h>
#include <sys/vnode_internal.h>
#include <sys/buf_internal.h>

#include <kern/kalloc.h>

#include <sys/kauth.h>
#include <IOKit/IOBSD.h>

#include <vfs/vfs_disk_conditioner.h>

#define DISK_CONDITIONER_SET_ENTITLEMENT "com.apple.private.dmc.set"

// number of total blocks for a mount
#define BLK_MAX(mp) ((mp->mnt_vfsstat.f_blocks * mp->mnt_vfsstat.f_bsize) / (mp->mnt_devblocksize))

// approx. time to spin up an idle HDD
#define DISK_SPINUP_SEC (8)

// idle period until assumed disk spin down
#define DISK_IDLE_SEC (10 * 60)

struct _disk_conditioner_info_t {
	boolean_t enabled; // if other fields have any effect
	uint64_t access_time_usec; // maximum latency before an I/O transfer begins
	uint64_t read_throughput_mbps; // throughput of an I/O read
	uint64_t write_throughput_mbps; // throughput of an I/O write
	boolean_t is_ssd; // behave like an SSD (for both conditioning and affecting behavior in other parts of VFS)
	daddr64_t last_blkno; // approx. last transfered block for simulating seek times
	struct timeval last_io_timestamp; // the last time an I/O completed
};

void disk_conditioner_delay(buf_t, int, int, uint64_t);
void disk_conditioner_unmount(mount_t mp);

extern void throttle_info_mount_reset_period(mount_t, int isssd);

static double
weighted_scale_factor(double scale)
{
	// 0 to 1 increasing quickly from 0. This weights smaller blkdiffs higher to add a type of minimum latency
	// I would like to use log(10) / 2.0 + 1, but using different approximation due to no math library
	// y = (x-1)^3 + 1
	double x_m1 = scale - 1;
	return x_m1 * x_m1 * x_m1 + 1;
}

void
disk_conditioner_delay(buf_t bp, int extents, int total_size, uint64_t already_elapsed_usec)
{
	mount_t mp;
	uint64_t delay_usec;
	daddr64_t blkdiff;
	daddr64_t last_blkno;
	double access_time_scale;
	struct _disk_conditioner_info_t *info = NULL;
	struct timeval elapsed;
	struct timeval start;

	mp = buf_vnode(bp)->v_mount;
	if (!mp) {
		return;
	}

	info = mp->mnt_disk_conditioner_info;
	if (!info || !info->enabled) {
		return;
	}

	if (!info->is_ssd) {
		// calculate approximate seek time based on difference in block number
		last_blkno = info->last_blkno;
		blkdiff = bp->b_blkno > last_blkno ? bp->b_blkno - last_blkno : last_blkno - bp->b_blkno;
		info->last_blkno = bp->b_blkno + bp->b_bcount;
	} else {
		blkdiff = BLK_MAX(mp);
	}

	// scale access time by (distance in blocks from previous I/O / maximum blocks)
	access_time_scale = weighted_scale_factor((double)blkdiff / BLK_MAX(mp));
	// most cases should pass in extents==1 for optimal delay calculation, otherwise just multiply delay by extents
	delay_usec = (uint64_t)(((uint64_t)extents * info->access_time_usec) * access_time_scale);

	if (info->read_throughput_mbps && (bp->b_flags & B_READ)) {
		delay_usec += (uint64_t)(total_size / ((double)(info->read_throughput_mbps * 1024 * 1024 / 8) / USEC_PER_SEC));
	} else if (info->write_throughput_mbps && !(bp->b_flags & B_READ)) {
		delay_usec += (uint64_t)(total_size / ((double)(info->write_throughput_mbps * 1024 * 1024 / 8) / USEC_PER_SEC));
	}

	// try simulating disk spinup based on time since last I/O
	if (!info->is_ssd) {
		microuptime(&elapsed);
		timevalsub(&elapsed, &info->last_io_timestamp);
		// avoid this delay right after boot (assuming last_io_timestamp is 0 and disk is already spinning)
		if (elapsed.tv_sec > DISK_IDLE_SEC && info->last_io_timestamp.tv_sec != 0) {
			delay_usec += DISK_SPINUP_SEC * USEC_PER_SEC;
		}
	}

	if (delay_usec <= already_elapsed_usec) {
		microuptime(&info->last_io_timestamp);
		return;
	}

	delay_usec -= already_elapsed_usec;

	while (delay_usec) {
		microuptime(&start);
		delay(delay_usec);
		microuptime(&elapsed);
		timevalsub(&elapsed, &start);
		if (elapsed.tv_sec * USEC_PER_SEC < delay_usec) {
			delay_usec -= elapsed.tv_sec * USEC_PER_SEC;
		} else {
			break;
		}
		if ((uint64_t)elapsed.tv_usec < delay_usec) {
			delay_usec -= elapsed.tv_usec;
		} else {
			break;
		}
	}

	microuptime(&info->last_io_timestamp);
}

int
disk_conditioner_get_info(mount_t mp, disk_conditioner_info *uinfo)
{
	struct _disk_conditioner_info_t *info;

	if (!mp) {
		return EINVAL;
	}

	info = mp->mnt_disk_conditioner_info;

	if (!info) {
		return 0;
	}

	uinfo->enabled = info->enabled;
	uinfo->access_time_usec = info->access_time_usec;
	uinfo->read_throughput_mbps = info->read_throughput_mbps;
	uinfo->write_throughput_mbps = info->write_throughput_mbps;
	uinfo->is_ssd = info->is_ssd;

	return 0;
}

int
disk_conditioner_set_info(mount_t mp, disk_conditioner_info *uinfo)
{
	struct _disk_conditioner_info_t *info;

	if (!kauth_cred_issuser(kauth_cred_get()) || !IOTaskHasEntitlement(current_task(), DISK_CONDITIONER_SET_ENTITLEMENT)) {
		return EPERM;
	}

	if (!mp) {
		return EINVAL;
	}

	info = mp->mnt_disk_conditioner_info;
	if (!info) {
		info = mp->mnt_disk_conditioner_info = kalloc(sizeof(struct _disk_conditioner_info_t));
		bzero(info, sizeof(struct _disk_conditioner_info_t));
	}

	info->enabled = uinfo->enabled;
	info->access_time_usec = uinfo->access_time_usec;
	info->read_throughput_mbps = uinfo->read_throughput_mbps;
	info->write_throughput_mbps = uinfo->write_throughput_mbps;
	info->is_ssd = uinfo->is_ssd;
	microuptime(&info->last_io_timestamp);

	// make sure throttling picks up the new periods
	throttle_info_mount_reset_period(mp, info->is_ssd);

	return 0;
}

void
disk_conditioner_unmount(mount_t mp)
{
	if (!mp->mnt_disk_conditioner_info) {
		return;
	}
	kfree(mp->mnt_disk_conditioner_info, sizeof(struct _disk_conditioner_info_t));
	mp->mnt_disk_conditioner_info = NULL;
}

boolean_t
disk_conditioner_mount_is_ssd(mount_t mp)
{
	struct _disk_conditioner_info_t *info = mp->mnt_disk_conditioner_info;

	if (!info || !info->enabled) {
		return (mp->mnt_kern_flag & MNTK_SSD);
	}

	return info->is_ssd;
}
