/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
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

#ifndef	_I386_LOCKS_H_
#define	_I386_LOCKS_H_

#include <sys/appleapiopts.h>
#include <kern/kern_types.h>

#ifdef	MACH_KERNEL_PRIVATE

#include <i386/hw_lock_types.h>

extern	unsigned int	LcksOpts;

#define enaLkDeb		0x00000001	/* Request debug in default attribute */
#define enaLkStat		0x00000002	/* Request statistic in default attribute */

#endif

#ifdef	MACH_KERNEL_PRIVATE
typedef struct {
	unsigned int    lck_spin_data[10];	/* XXX - usimple_lock_data_t */
} lck_spin_t;

#define	LCK_SPIN_TAG_DESTROYED		0x00002007	/* lock marked as Destroyed */

#else
#ifdef	KERNEL_PRIVATE
typedef struct {
	unsigned int    opaque[10];
} lck_spin_t;
#else
typedef	struct __lck_spin_t__	lck_spin_t;
#endif
#endif

#ifdef	MACH_KERNEL_PRIVATE
typedef struct _lck_mtx_ {
	union {
		struct {
			unsigned int			lck_mtxd_ilk;
			unsigned int			lck_mtxd_locked;
			unsigned short			lck_mtxd_waiters;
			unsigned short			lck_mtxd_pri;
		} lck_mtxd;
		struct {
			unsigned int			lck_mtxi_tag;
			struct _lck_mtx_ext_	*lck_mtxi_ptr;
			unsigned int			lck_mtxi_pad8;
		} lck_mtxi;
	} lck_mtx_sw;
} lck_mtx_t;

#define	lck_mtx_ilk	lck_mtx_sw.lck_mtxd.lck_mtxd_ilk
#define	lck_mtx_locked	lck_mtx_sw.lck_mtxd.lck_mtxd_locked
#define	lck_mtx_waiters	lck_mtx_sw.lck_mtxd.lck_mtxd_waiters
#define	lck_mtx_pri	lck_mtx_sw.lck_mtxd.lck_mtxd_pri

#define lck_mtx_tag	lck_mtx_sw.lck_mtxi.lck_mtxi_tag
#define lck_mtx_ptr	lck_mtx_sw.lck_mtxi.lck_mtxi_ptr

#define	LCK_MTX_TAG_INDIRECT			0x00001007	/* lock marked as Indirect  */
#define	LCK_MTX_TAG_DESTROYED			0x00002007	/* lock marked as Destroyed */

typedef struct {
	unsigned int		type;
	vm_offset_t		pc;
	vm_offset_t		thread;
} lck_mtx_deb_t;

#define MUTEX_TAG       0x4d4d

typedef struct {
	unsigned int		lck_mtx_stat_data;
} lck_mtx_stat_t;

typedef struct _lck_mtx_ext_ {
	lck_mtx_t		lck_mtx;
	struct _lck_grp_	*lck_mtx_grp;
	unsigned int		lck_mtx_attr;
	lck_mtx_deb_t		lck_mtx_deb;
	lck_mtx_stat_t		lck_mtx_stat;
} lck_mtx_ext_t;

#define	LCK_MTX_ATTR_DEBUG	0x1
#define	LCK_MTX_ATTR_DEBUGb	31
#define	LCK_MTX_ATTR_STAT	0x2
#define	LCK_MTX_ATTR_STATb	30

#else
#ifdef	KERNEL_PRIVATE
typedef struct {
	unsigned int		opaque[3];
} lck_mtx_t;
#else
typedef struct __lck_mtx_t__	lck_mtx_t;
#endif
#endif

#ifdef	MACH_KERNEL_PRIVATE
typedef struct {
	hw_lock_data_t		interlock;
	volatile unsigned int
						read_count:16,	/* No. of accepted readers */
						want_upgrade:1,	/* Read-to-write upgrade waiting */
						want_write:1,	/* Writer is waiting, or locked for write */
						waiting:1,		/* Someone is sleeping on lock */
						can_sleep:1;	/* Can attempts to lock go to sleep? */
	unsigned int		lck_rw_tag;
} lck_rw_t;

#define	LCK_RW_TAG_DESTROYED		0x00002007	/* lock marked as Destroyed */

#else
#ifdef	KERNEL_PRIVATE
typedef struct {
	unsigned int		opaque[3];
} lck_rw_t;
#else
typedef struct __lck_rw_t__	lck_rw_t;
#endif
#endif

#endif	/* _I386_LOCKS_H_ */
