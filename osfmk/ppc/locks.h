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

#ifndef	_PPC_LOCKS_H_
#define	_PPC_LOCKS_H_

#include <kern/kern_types.h>
#ifdef	MACH_KERNEL_PRIVATE
#include <ppc/hw_lock_types.h>
#endif


#ifdef	MACH_KERNEL_PRIVATE

extern	unsigned int	LcksOpts;

#define enaLkDeb		0x00000001	/* Request debug in default attribute */
#define enaLkStat		0x00000002	/* Request statistic in default attribute */

#define disLkType		0x80000000	/* Disable type checking */
#define disLktypeb		0
#define disLkThread		0x40000000	/* Disable ownership checking */
#define disLkThreadb	1
#define enaLkExtStck	0x20000000	/* Enable extended backtrace */
#define enaLkExtStckb	2
#define disLkMyLck		0x10000000	/* Disable recursive lock dectection */
#define disLkMyLckb		3

#endif

#ifdef	MACH_KERNEL_PRIVATE
typedef struct {
	unsigned int		interlock;
	unsigned int		lck_spin_pad4[2];
} lck_spin_t;

#define	LCK_SPIN_TAG_DESTROYED		0x00002007	/* lock marked as Destroyed */

#else
#ifdef	KERNEL_PRIVATE
typedef struct {
	unsigned int   		 opaque[3];
} lck_spin_t;
#else
typedef struct __lck_spin_t__	lck_spin_t;
#endif
#endif

#ifdef	MACH_KERNEL_PRIVATE
typedef struct _lck_mtx_ {
	union {
		struct {
			unsigned int			lck_mtxd_data;
			unsigned short			lck_mtxd_waiters;
			unsigned short			lck_mtxd_pri;
			unsigned int			lck_mtxd_pad8;
		} lck_mtxd;
		struct {
			unsigned int			lck_mtxi_tag;
			struct _lck_mtx_ext_	*lck_mtxi_ptr;
			unsigned int			lck_mtxi_pad8;
		} lck_mtxi;
	} lck_mtx_sw; 
} lck_mtx_t;

#define	lck_mtx_data	lck_mtx_sw.lck_mtxd.lck_mtxd_data
#define	lck_mtx_waiters	lck_mtx_sw.lck_mtxd.lck_mtxd_waiters
#define	lck_mtx_pri		lck_mtx_sw.lck_mtxd.lck_mtxd_pri

#define lck_mtx_tag	lck_mtx_sw.lck_mtxi.lck_mtxi_tag
#define lck_mtx_ptr		lck_mtx_sw.lck_mtxi.lck_mtxi_ptr

#define	LCK_MTX_TAG_INDIRECT			0x00001007	/* lock marked as Indirect  */
#define	LCK_MTX_TAG_DESTROYED			0x00002007	/* lock marked as Destroyed */

#define	LCK_FRAMES_MAX	8

typedef struct {
	unsigned int		type;
	vm_offset_t			stack[LCK_FRAMES_MAX];
	vm_offset_t			thread;
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
	/* Unused on PowerPC */
	lck_mtx_stat_t		lck_mtx_stat;
} lck_mtx_ext_t;

#define	LCK_MTX_ATTR_DEBUG	0x1
#define	LCK_MTX_ATTR_DEBUGb	31
#define	LCK_MTX_ATTR_STAT	0x2
#define	LCK_MTX_ATTR_STATb	30

#else
#ifdef	KERNEL_PRIVATE
typedef struct {
    unsigned int   		 opaque[3];
} lck_mtx_t;

typedef struct {
    unsigned int   		 opaque[16];
} lck_mtx_ext_t;
#else
typedef struct __lck_mtx_t__		lck_mtx_t;
typedef struct __lck_mtx_ext_t__	lck_mtx_ext_t;
#endif
#endif

#ifdef	MACH_KERNEL_PRIVATE
typedef struct {
	union {
		struct {
			unsigned int			lck_rwd_shared_cnt:16,	/* No. of shared granted request */
									lck_rwd_priv_excl:1,	/* priority for Writer */
									lck_rwd_pad17:11,		/* padding */
									lck_rwd_want_excl:1,	/* Writer is waiting, or locked for write */
									lck_rwd_want_upgrade:1,	/* Read-to-write upgrade waiting */
									lck_rwd_waiting:1,		/* Someone is sleeping on lock */
									lck_rwd_interlock:1;	/* Read-to-write upgrade waiting */
			unsigned int			lck_rwd_pad4;
			unsigned int			lck_rwd_pad8;
		} lck_rwd;
		struct {
			unsigned int			lck_rwi_tag;
			struct _lck_rw_ext_	*lck_rwi_ptr;
			unsigned int			lck_rwi_pad8;
		} lck_rwi;
	} lck_rw_sw; 
} lck_rw_t;

#define	lck_rw_interlock		lck_rw_sw.lck_rwd.lck_rwd_interlock
#define	lck_rw_want_upgrade		lck_rw_sw.lck_rwd.lck_rwd_want_upgrade
#define	lck_rw_want_excl		lck_rw_sw.lck_rwd.lck_rwd_want_excl
#define	lck_rw_waiting			lck_rw_sw.lck_rwd.lck_rwd_waiting
#define	lck_rw_priv_excl		lck_rw_sw.lck_rwd.lck_rwd_priv_excl
#define	lck_rw_shared_cnt		lck_rw_sw.lck_rwd.lck_rwd_shared_cnt

#define lck_rw_tag				lck_rw_sw.lck_rwi.lck_rwi_tag
#define lck_rw_ptr				lck_rw_sw.lck_rwi.lck_rwi_ptr

typedef struct {
	unsigned int		type;
	vm_offset_t			stack[LCK_FRAMES_MAX];
	thread_t			thread;
	void 				(*pc_excl)(void);
	void 				(*pc_done)(void);
} lck_rw_deb_t;

#define RW_TAG       0x5d5d

typedef struct {
	unsigned int		lck_rw_stat_data;
} lck_rw_stat_t;

typedef struct _lck_rw_ext_ {
	lck_rw_t		lck_rw;
	struct _lck_grp_	*lck_rw_grp;
	unsigned int		lck_rw_attr;
	lck_rw_deb_t		lck_rw_deb;
	lck_rw_stat_t		lck_rw_stat;
} lck_rw_ext_t;

#define	LCK_RW_ATTR_DEBUG	0x1
#define	LCK_RW_ATTR_DEBUGb	31
#define	LCK_RW_ATTR_STAT	0x2
#define	LCK_RW_ATTR_STATb	30
#define	LCK_RW_ATTR_DIS_THREAD	0x40000000
#define	LCK_RW_ATTR_DIS_THREADb	1
#define	LCK_RW_ATTR_DIS_MYLOCK	0x10000000
#define	LCK_RW_ATTR_DIS_MYLOCKb	3

#define	LCK_RW_TAG_INDIRECT			0x00001107	/* lock marked as Indirect  */
#define	LCK_RW_TAG_DESTROYED		0x00002107	/* lock marked as Destroyed */

#else
#ifdef	KERNEL_PRIVATE
typedef struct {
    unsigned int   		 opaque[3];
} lck_rw_t;
#else
typedef	struct __lck_rw_t__	lck_rw_t;
#endif
#endif

#endif	/* _PPC_LOCKS_H_ */
