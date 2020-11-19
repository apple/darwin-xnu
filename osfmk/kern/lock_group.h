/*
 * Copyright (c) 2018 Apple Computer, Inc. All rights reserved.
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
#ifndef _KERN_LOCK_GROUP_H
#define _KERN_LOCK_GROUP_H

#include <kern/queue.h>
#include <mach/mach_types.h>

__BEGIN_DECLS

#define LCK_GRP_NULL    (lck_grp_t *)NULL

typedef enum lck_type {
	LCK_TYPE_SPIN,
	LCK_TYPE_MTX,
	LCK_TYPE_RW,
	LCK_TYPE_TICKET
} lck_type_t;

#if XNU_KERNEL_PRIVATE
#include <kern/startup.h>
#include <os/refcnt.h>

/*
 * Arguments wrapped in LCK_GRP_ARG() will be elided
 * when LOCK_STATS is not set.
 *
 * Arguments wrapped with LCK_GRP_PROBEARG() will be
 * NULL when LOCK_STATS is not set
 */
#if LOCK_STATS
#define LCK_GRP_ARG(expr) ,expr
#define LCK_GRP_PROBEARG(grp) grp
#else
#define LCK_GRP_ARG(expr)
#define LCK_GRP_PROBEARG(grp) LCK_GRP_NULL
#endif /* LOCK_STATS */

typedef struct _lck_grp_stat_ {
	uint64_t lgs_count;
	uint32_t lgs_enablings;
#if CONFIG_DTRACE
	/*
	 * Protected by dtrace_lock
	 */
	uint32_t lgs_probeid;
	uint64_t lgs_limit;
#endif /* CONFIG_DTRACE */
} lck_grp_stat_t;

typedef struct _lck_grp_stats_ {
#if LOCK_STATS
	lck_grp_stat_t          lgss_spin_held;
	lck_grp_stat_t          lgss_spin_miss;
	lck_grp_stat_t          lgss_spin_spin;
	lck_grp_stat_t          lgss_ticket_held;
	lck_grp_stat_t          lgss_ticket_miss;
	lck_grp_stat_t          lgss_ticket_spin;
#endif /* LOCK_STATS */

	lck_grp_stat_t          lgss_mtx_held;
	lck_grp_stat_t          lgss_mtx_direct_wait;
	lck_grp_stat_t          lgss_mtx_miss;
	lck_grp_stat_t          lgss_mtx_wait;
} lck_grp_stats_t;

#define LCK_GRP_MAX_NAME        64

typedef struct _lck_grp_ {
	queue_chain_t           lck_grp_link;
	os_refcnt_t             lck_grp_refcnt;
	uint32_t                lck_grp_spincnt;
	uint32_t                lck_grp_ticketcnt;
	uint32_t                lck_grp_mtxcnt;
	uint32_t                lck_grp_rwcnt;
	uint32_t                lck_grp_attr;
	char                    lck_grp_name[LCK_GRP_MAX_NAME];
	lck_grp_stats_t         lck_grp_stats;
} lck_grp_t;

#else
typedef struct _lck_grp_ lck_grp_t;
#endif /* XNU_KERNEL_PRIVATE */

#define LCK_GRP_ATTR_STAT       0x1
#define LCK_GRP_ATTR_TIME_STAT  0x2

#ifdef XNU_KERNEL_PRIVATE
typedef struct _lck_grp_attr_ {
	uint32_t        grp_attr_val;
} lck_grp_attr_t;

struct lck_grp_attr_startup_spec {
	lck_grp_attr_t *grp_attr;
	uint32_t        grp_attr_set_flags;
	uint32_t        grp_attr_clear_flags;
};

struct lck_grp_startup_spec {
	lck_grp_t      *grp;
	const char     *grp_name;
	lck_grp_attr_t *grp_attr;
};

extern void lck_grp_attr_startup_init(
	struct lck_grp_attr_startup_spec *spec);

extern void lck_grp_startup_init(
	struct lck_grp_startup_spec *spec);

/*
 * Auto-initializing lock group declarations
 * -----------------------------------------
 *
 * Use LCK_GRP_DECLARE to declare an automatically initialized group.
 *
 * Unless you need to configure your lock groups in very specific ways,
 * there is no point creating explicit lock group attributes. If however
 * you do need to tune the group, then LCK_GRP_DECLARE_ATTR can be used
 * and takes an extra lock group attr argument previously declared with
 * LCK_GRP_ATTR_DECLARE.
 */
#define LCK_GRP_ATTR_DECLARE(var, set_flags, clear_flags) \
	SECURITY_READ_ONLY_LATE(lck_grp_attr_t) var; \
	static __startup_data struct lck_grp_attr_startup_spec \
	__startup_lck_grp_attr_spec_ ## var = { &var, set_flags, clear_flags }; \
	STARTUP_ARG(LOCKS_EARLY, STARTUP_RANK_SECOND, lck_grp_attr_startup_init, \
	    &__startup_lck_grp_attr_spec_ ## var)

#define LCK_GRP_DECLARE_ATTR(var, name, attr) \
	__PLACE_IN_SECTION("__DATA,__lock_grp") lck_grp_t var; \
	static __startup_data struct lck_grp_startup_spec \
	__startup_lck_grp_spec_ ## var = { &var, name, attr }; \
	STARTUP_ARG(LOCKS_EARLY, STARTUP_RANK_THIRD, lck_grp_startup_init, \
	    &__startup_lck_grp_spec_ ## var)

#define LCK_GRP_DECLARE(var, name) \
	LCK_GRP_DECLARE_ATTR(var, name, LCK_GRP_ATTR_NULL);

#else
typedef struct __lck_grp_attr__ lck_grp_attr_t;
#endif /* XNU_KERNEL_PRIVATE */

#define LCK_GRP_ATTR_NULL       (lck_grp_attr_t *)NULL

extern  lck_grp_attr_t  *lck_grp_attr_alloc_init(
	void);

extern  void            lck_grp_attr_setdefault(
	lck_grp_attr_t          *attr);

extern  void            lck_grp_attr_setstat(
	lck_grp_attr_t          *attr);

extern  void            lck_grp_attr_free(
	lck_grp_attr_t          *attr);

extern  lck_grp_t       *lck_grp_alloc_init(
	const char*             grp_name,
	lck_grp_attr_t  *attr);

extern void             lck_grp_free(
	lck_grp_t               *grp);

#ifdef  MACH_KERNEL_PRIVATE
extern  void            lck_grp_init(
	lck_grp_t               *grp,
	const char*             grp_name,
	lck_grp_attr_t          *attr);

extern  void            lck_grp_reference(
	lck_grp_t               *grp);

extern  void            lck_grp_deallocate(
	lck_grp_t                *grp);

extern  void            lck_grp_lckcnt_incr(
	lck_grp_t               *grp,
	lck_type_t              lck_type);

extern  void            lck_grp_lckcnt_decr(
	lck_grp_t               *grp,
	lck_type_t              lck_type);
#endif /* MACH_KERNEL_PRIVATE */

__END_DECLS

#endif /* _KERN_LOCK_GROUP_H */
