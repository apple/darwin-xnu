/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
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
#include <sys/ioctl.h>

#include <sys/stat.h>
#include <miscfs/devfs/devfs.h>
#include <sys/conf.h>
#include <sys/systm.h>
#include <sys/dtrace.h>
#include <sys/dtrace_impl.h>
#include <kern/lock_group.h>
#include <kern/lock_stat.h>

#if LOCK_STATS

#define LP_NODE "lockprof"

#define LOCKPROF_AFRAMES 3
#define LOCKPROF_LEN 64

static dtrace_provider_id_t lockprof_id;

decl_lck_mtx_data(extern, lck_grp_lock);
extern queue_head_t lck_grp_queue;
extern unsigned int lck_grp_cnt;

extern void lck_grp_reference(lck_grp_t *grp);
extern void lck_grp_deallocate(lck_grp_t *grp);

#define LOCKPROF_MAX 10000 /* maximum number of lockprof probes */
static uint32_t lockprof_count; /* current number of lockprof probes */

enum probe_flags {
	/*
	 * Counts time spent spinning/blocking
	 */
	TIME_EVENT = 0x01,
	/*
	 * Requires LCK_GRP_ATTR_STAT to be set on the lock
	 * group, either via lck_grp_attr_setsta on the lock group,
	 * or globally via the lcks=3 boot-arg
	 */
	STAT_NEEDED = 0x02
};

static const struct {
	const char *prefix;
	int flags;
	size_t count_offset;
	size_t stat_offset;
} probes[] = {
	{"spin-held-", 0, offsetof(lck_grp_t, lck_grp_spincnt), offsetof(lck_grp_stats_t, lgss_spin_held)},
	{"spin-miss-", 0, offsetof(lck_grp_t, lck_grp_spincnt), offsetof(lck_grp_stats_t, lgss_spin_miss)},
	{"spin-spin-", TIME_EVENT, offsetof(lck_grp_t, lck_grp_spincnt), offsetof(lck_grp_stats_t, lgss_spin_spin)},
	{"ticket-held-", 0, offsetof(lck_grp_t, lck_grp_ticketcnt), offsetof(lck_grp_stats_t, lgss_ticket_held)},
	{"ticket-miss-", 0, offsetof(lck_grp_t, lck_grp_ticketcnt), offsetof(lck_grp_stats_t, lgss_ticket_miss)},
	{"ticket-spin-", TIME_EVENT, offsetof(lck_grp_t, lck_grp_ticketcnt), offsetof(lck_grp_stats_t, lgss_ticket_spin)},
#if HAS_EXT_MUTEXES
	{"adaptive-held-", STAT_NEEDED, offsetof(lck_grp_t, lck_grp_mtxcnt), offsetof(lck_grp_stats_t, lgss_mtx_held)},
	{"adaptive-miss-", STAT_NEEDED, offsetof(lck_grp_t, lck_grp_mtxcnt), offsetof(lck_grp_stats_t, lgss_mtx_miss)},
	{"adaptive-wait-", STAT_NEEDED, offsetof(lck_grp_t, lck_grp_mtxcnt), offsetof(lck_grp_stats_t, lgss_mtx_wait)},
	{"adaptive-direct-wait-", STAT_NEEDED, offsetof(lck_grp_t, lck_grp_mtxcnt), offsetof(lck_grp_stats_t, lgss_mtx_direct_wait)},
#endif /* HAS_EXT_MUTEXES */
	{NULL, false, 0, 0}
};

/*
 * Default defined probes for counting events
 */
const static int hold_defaults[] = {
	10000 /* 10000 events */
};

/*
 * Default defined probes for time events
 */
const static struct {
	unsigned int time;
	const char *suffix;
	uint64_t mult;
} cont_defaults[] = {
	{100, "ms", NANOSEC / MILLISEC} /* 100 ms */
};

typedef struct lockprof_probe {
	int lockprof_kind;
	dtrace_id_t lockprof_id;
	uint64_t lockprof_limit;
	lck_grp_t *lockprof_grp;
} lockprof_probe_t;

void
lockprof_invoke(lck_grp_t *grp, lck_grp_stat_t *stat, uint64_t val)
{
	dtrace_probe(stat->lgs_probeid, (uintptr_t)grp, val, 0, 0, 0);
}

static int
lockprof_lock_count(lck_grp_t *grp, int kind)
{
	return *(int*)((void*)(grp) + probes[kind].count_offset);
}

static void
probe_create(int kind, const char *suffix, const char *grp_name, uint64_t count, uint64_t mult)
{
	char name[LOCKPROF_LEN];
	lck_mtx_lock(&lck_grp_lock);
	lck_grp_t *grp = (lck_grp_t*)queue_first(&lck_grp_queue);
	uint64_t limit = count * mult;

	if (probes[kind].flags & TIME_EVENT) {
		nanoseconds_to_absolutetime(limit, &limit);
	}

	for (unsigned int i = 0; i < lck_grp_cnt; i++, grp = (lck_grp_t*)queue_next((queue_entry_t)grp)) {
		if (!grp_name || grp_name[0] == '\0' || strcmp(grp_name, grp->lck_grp_name) == 0) {
			snprintf(name, sizeof(name), "%s%llu%s", probes[kind].prefix, count, suffix ?: "");

			if (dtrace_probe_lookup(lockprof_id, grp->lck_grp_name, NULL, name) != 0) {
				continue;
			}
			if (lockprof_lock_count(grp, kind) == 0) {
				continue;
			}
			if ((probes[kind].flags & STAT_NEEDED) && !(grp->lck_grp_attr & LCK_GRP_ATTR_STAT)) {
				continue;
			}
			if (lockprof_count >= LOCKPROF_MAX) {
				break;
			}

			lockprof_probe_t *probe = kmem_zalloc(sizeof(lockprof_probe_t), KM_SLEEP);
			probe->lockprof_kind = kind;
			probe->lockprof_limit = limit;
			probe->lockprof_grp = grp;

			lck_grp_reference(grp);

			probe->lockprof_id = dtrace_probe_create(lockprof_id, grp->lck_grp_name, NULL, name,
			    LOCKPROF_AFRAMES, probe);

			lockprof_count++;
		}
	}
	lck_mtx_unlock(&lck_grp_lock);
}

static void
lockprof_provide(void *arg, const dtrace_probedesc_t *desc)
{
#pragma unused(arg)
	size_t event_id, i, j, len;

	if (desc == NULL) {
		for (i = 0; i < sizeof(hold_defaults) / sizeof(hold_defaults[0]); i++) {
			for (j = 0; probes[j].prefix != NULL; j++) {
				if (!(probes[j].flags & TIME_EVENT)) {
					probe_create(j, NULL, NULL, hold_defaults[i], 1);
				}
			}
		}
		for (i = 0; i < sizeof(cont_defaults) / sizeof(cont_defaults[0]); i++) {
			for (j = 0; probes[j].prefix != NULL; j++) {
				if (probes[j].flags & TIME_EVENT) {
					probe_create(j, cont_defaults[i].suffix, NULL, cont_defaults[i].time, cont_defaults[i].mult);
				}
			}
		}
		return;
	}

	const char *name, *suffix = NULL;
	hrtime_t val = 0, mult = 1;

	const struct {
		const char *name;
		hrtime_t mult;
	} suffixes[] = {
		{ "us", NANOSEC / MICROSEC },
		{ "usec", NANOSEC / MICROSEC },
		{ "ms", NANOSEC / MILLISEC },
		{ "msec", NANOSEC / MILLISEC },
		{ "s", NANOSEC / SEC },
		{ "sec", NANOSEC / SEC },
		{ NULL, 0 }
	};

	name = desc->dtpd_name;

	for (event_id = 0; probes[event_id].prefix != NULL; event_id++) {
		len = strlen(probes[event_id].prefix);

		if (strncmp(name, probes[event_id].prefix, len) != 0) {
			continue;
		}
		break;
	}

	if (probes[event_id].prefix == NULL) {
		return;
	}


	/*
	 * We need to start before any time suffix.
	 */
	for (i = strlen(name); i >= len; i--) {
		if (name[i] >= '0' && name[i] <= '9') {
			break;
		}
		suffix = &name[i];
	}

	/*
	 * Now determine the numerical value present in the probe name.
	 */
	for (uint64_t m = 1; i >= len; i--) {
		if (name[i] < '0' || name[i] > '9') {
			return;
		}

		val += (name[i] - '0') * m;
		m *= (hrtime_t)10;
	}

	if (val == 0) {
		return;
	}

	if (probes[event_id].flags & TIME_EVENT) {
		for (i = 0, mult = 0; suffixes[i].name != NULL; i++) {
			if (strncasecmp(suffixes[i].name, suffix, strlen(suffixes[i].name) + 1) == 0) {
				mult = suffixes[i].mult;
				break;
			}
		}
		if (suffixes[i].name == NULL) {
			return;
		}
	} else if (*suffix != '\0') {
		return;
	}

	probe_create(event_id, suffix, desc->dtpd_mod, val, mult);
}


static lck_grp_stat_t*
lockprof_stat(lck_grp_t *grp, int kind)
{
	return (lck_grp_stat_t*)((void*)&grp->lck_grp_stats + probes[kind].stat_offset);
}

static int
lockprof_enable(void *arg, dtrace_id_t id, void *parg)
{
#pragma unused(arg, id, parg)
	lockprof_probe_t *probe = (lockprof_probe_t*)parg;
	lck_grp_t *grp = probe->lockprof_grp;
	lck_grp_stat_t *stat;

	if (grp == NULL) {
		return -1;
	}

	if ((stat = lockprof_stat(grp, probe->lockprof_kind)) == NULL) {
		return -1;
	}

	/*
	 * lockprof_enable/disable are called with
	 * dtrace_lock held
	 */
	if (stat->lgs_limit != 0) {
		return -1;
	}

	stat->lgs_limit = probe->lockprof_limit;
	stat->lgs_enablings++;
	stat->lgs_probeid = probe->lockprof_id;

	return 0;
}

static void
lockprof_disable(void *arg, dtrace_id_t id, void *parg)
{
#pragma unused(arg, id)
	lockprof_probe_t *probe = (lockprof_probe_t*)parg;
	lck_grp_t *grp = probe->lockprof_grp;
	lck_grp_stat_t *stat;

	if (grp == NULL) {
		return;
	}

	if ((stat = lockprof_stat(grp, probe->lockprof_kind)) == NULL) {
		return;
	}

	if (stat->lgs_limit == 0 || stat->lgs_enablings == 0) {
		return;
	}

	stat->lgs_limit = 0;
	stat->lgs_enablings--;
	stat->lgs_probeid = 0;
}

static void
lockprof_destroy(void *arg, dtrace_id_t id, void *parg)
{
#pragma unused(arg, id)
	lockprof_probe_t *probe = (lockprof_probe_t*)parg;
	lck_grp_deallocate(probe->lockprof_grp);
	kmem_free(probe, sizeof(lockprof_probe_t));
	lockprof_count--;
}

static void
lockprof_getargdesc(void *arg, dtrace_id_t id, void *parg, dtrace_argdesc_t *desc)
{
#pragma unused(arg, id, parg)
	const char *argdesc = NULL;
	switch (desc->dtargd_ndx) {
	case 0:
		argdesc = "lck_grp_t*";
		break;
	case 1:
		argdesc = "uint64_t";
		break;
	}

	if (argdesc) {
		strlcpy(desc->dtargd_native, argdesc, DTRACE_ARGTYPELEN);
	} else {
		desc->dtargd_ndx = DTRACE_ARGNONE;
	}
}
static dtrace_pattr_t lockprof_attr = {
	{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON },
	{ DTRACE_STABILITY_UNSTABLE, DTRACE_STABILITY_UNSTABLE, DTRACE_CLASS_UNKNOWN },
	{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
	{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON },
	{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON },
};

static dtrace_pops_t lockprof_pops = {
	.dtps_provide =         lockprof_provide,
	.dtps_provide_module =  NULL,
	.dtps_enable =          lockprof_enable,
	.dtps_disable =         lockprof_disable,
	.dtps_suspend =         NULL,
	.dtps_resume =          NULL,
	.dtps_getargdesc =      lockprof_getargdesc,
	.dtps_getargval =       NULL,
	.dtps_usermode =        NULL,
	.dtps_destroy =         lockprof_destroy
};

static int
_lockprof_open(dev_t dev, int flags, int devtype, struct proc *p)
{
#pragma unused(dev,flags,devtype,p)
	return 0;
}

static const struct cdevsw lockprof_cdevsw =
{
	.d_open = _lockprof_open,
	.d_close = eno_opcl,
	.d_read = eno_rdwrt,
	.d_write = eno_rdwrt,
	.d_ioctl = eno_ioctl,
	.d_stop = (stop_fcn_t *)nulldev,
	.d_reset = (reset_fcn_t *)nulldev,
	.d_select = eno_select,
	.d_mmap = eno_mmap,
	.d_strategy = eno_strat,
	.d_reserved_1 = eno_getc,
	.d_reserved_2 = eno_putc,
};


#endif /* LOCK_STATS */
void lockprof_init(void);
void
lockprof_init(void)
{
#if LOCK_STATS
	int majorno = cdevsw_add(-1, &lockprof_cdevsw);

	if (majorno < 0) {
		panic("dtrace: failed to allocate a major number");
		return;
	}

	if (dtrace_register(LP_NODE, &lockprof_attr, DTRACE_PRIV_KERNEL,
	    NULL, &lockprof_pops, NULL, &lockprof_id) != 0) {
		panic("dtrace: failed to register lockprof provider");
	}

	dev_t dev = makedev(majorno, 0);

	if (devfs_make_node( dev, DEVFS_CHAR, UID_ROOT, GID_WHEEL, 0666,
	    LP_NODE, 0 ) == NULL) {
		panic("dtrace: devfs_make_node failed for lockprof");
	}

#endif /* LOCK_STATS */
}
