/*
 * Copyright (c) 2006-2017 Apple Inc. All rights reserved.
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

#include <sys/errno.h>
#include <sys/types.h>
#include <kern/kalloc.h>
#include <sys/buf.h>
#include <sys/time.h>
#include <sys/kauth.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/syslog.h>
#include <sys/vnode_internal.h>
#include <sys/fslog.h>
#include <sys/mount_internal.h>
#include <sys/kasl.h>

#include <sys/queue.h>
#include <kern/zalloc.h>

#include <uuid/uuid.h>

#include <stdarg.h>

/* Log information about external modification of a process,
 * using MessageTracer formatting. Assumes that both the caller
 * and target are appropriately locked.
 * Currently prints following information -
 *      1. Caller process name (truncated to 16 characters)
 *	2. Caller process Mach-O UUID
 *  3. Target process name (truncated to 16 characters)
 *  4. Target process Mach-O UUID
 */
void
fslog_extmod_msgtracer(proc_t caller, proc_t target)
{
	if ((caller != PROC_NULL) && (target != PROC_NULL)) {
		/*
		 * Print into buffer large enough for "ThisIsAnApplicat(BC223DD7-B314-42E0-B6B0-C5D2E6638337)",
		 * including space for escaping, and NUL byte included in sizeof(uuid_string_t).
		 */

		uuid_string_t uuidstr;
		char c_name[2 * MAXCOMLEN + 2 /* () */ + sizeof(uuid_string_t)];
		char t_name[2 * MAXCOMLEN + 2 /* () */ + sizeof(uuid_string_t)];

		strlcpy(c_name, caller->p_comm, sizeof(c_name));
		uuid_unparse_upper(caller->p_uuid, uuidstr);
		strlcat(c_name, "(", sizeof(c_name));
		strlcat(c_name, uuidstr, sizeof(c_name));
		strlcat(c_name, ")", sizeof(c_name));
		if (0 != escape_str(c_name, strlen(c_name) + 1, sizeof(c_name))) {
			return;
		}

		strlcpy(t_name, target->p_comm, sizeof(t_name));
		uuid_unparse_upper(target->p_uuid, uuidstr);
		strlcat(t_name, "(", sizeof(t_name));
		strlcat(t_name, uuidstr, sizeof(t_name));
		strlcat(t_name, ")", sizeof(t_name));
		if (0 != escape_str(t_name, strlen(t_name) + 1, sizeof(t_name))) {
			return;
		}
#if DEBUG
		printf("EXTMOD: %s(%d) -> %s(%d)\n",
		    c_name,
		    proc_pid(caller),
		    t_name,
		    proc_pid(target));
#endif

		kern_asl_msg(LOG_DEBUG, "messagetracer",
		    5,
		    "com.apple.message.domain", "com.apple.kernel.external_modification",                                     /* 0 */
		    "com.apple.message.signature", c_name,                                     /* 1 */
		    "com.apple.message.signature2", t_name,                                     /* 2 */
		    "com.apple.message.result", "noop",                                     /* 3 */
		    "com.apple.message.summarize", "YES",                                     /* 4 */
		    NULL);
	}
}

#if defined(__x86_64__)

/*
 * Log information about floating point exception handling
 */

static lck_mtx_t fpxlock;

void
fpxlog_init(void)
{
	lck_grp_attr_t *lck_grp_attr = lck_grp_attr_alloc_init();
	lck_grp_t *lck_grp = lck_grp_alloc_init("fpx", lck_grp_attr);
	lck_mtx_init(&fpxlock, lck_grp, LCK_ATTR_NULL);
}

struct fpx_event {
	uuid_t fe_uuid;
	uint32_t fe_code;
	uint32_t fe_xcpt;
	TAILQ_ENTRY(fpx_event) fe_link;
};

static bool
match_fpx_event(const struct fpx_event *fe,
    const uuid_t uuid, const uint32_t code, const uint32_t xcpt)
{
	return code == fe->fe_code && xcpt == fe->fe_xcpt &&
	       0 == memcmp(uuid, fe->fe_uuid, sizeof(uuid_t));
}

#if FPX_EVENT_DBG
static __attribute__((noinline)) void
print_fpx_event(const char *pfx, const struct fpx_event *fe)
{
	uuid_string_t uustr;
	uuid_unparse_upper(fe->fe_uuid, uustr);
	printf("%s: code 0x%x xcpt 0x%x uuid '%s'\n",
	    pfx, fe->fe_code, fe->fe_xcpt, uustr);
}
#define DPRINTF_FPX_EVENT(pfx, fe)      print_fpx_event(pfx, fe)
#else
#define DPRINTF_FPX_EVENT(pfx, fe)      /* nothing */
#endif

#define MAX_DISTINCT_FPX_EVENTS 101     /* (approx one page of heap) */

/*
 * Filter to detect "new" <uuid, code, xcpt> tuples.
 * Uses limited amount of state, managed LRU.
 * Optimized to ignore repeated invocation with the same tuple.
 *
 * Note that there are 6 exception types, two types of FP, and
 * many binaries, so don't make the list bound too small.
 * It's also a linear search, so don't make it too large either.
 * Next level filtering provided by syslogd, and summarization.
 */
static bool
novel_fpx_event(const uuid_t uuid, uint32_t code, uint32_t xcpt)
{
	static TAILQ_HEAD(fpx_event_head, fpx_event) fehead =
	    TAILQ_HEAD_INITIALIZER(fehead);
	struct fpx_event *fe;

	lck_mtx_lock(&fpxlock);

	fe = TAILQ_FIRST(&fehead);
	if (NULL != fe &&
	    match_fpx_event(fe, uuid, code, xcpt)) {
		/* seen before and element already at head */
		lck_mtx_unlock(&fpxlock);
		DPRINTF_FPX_EVENT("seen, head", fe);
		return false;
	}

	unsigned int count = 0;

	TAILQ_FOREACH(fe, &fehead, fe_link) {
		if (match_fpx_event(fe, uuid, code, xcpt)) {
			/* seen before, now move element to head */
			TAILQ_REMOVE(&fehead, fe, fe_link);
			TAILQ_INSERT_HEAD(&fehead, fe, fe_link);
			lck_mtx_unlock(&fpxlock);
			DPRINTF_FPX_EVENT("seen, moved to head", fe);
			return false;
		}
		count++;
	}

	/* not recorded here => novel */

	if (count >= MAX_DISTINCT_FPX_EVENTS) {
		/* reuse LRU element */
		fe = TAILQ_LAST(&fehead, fpx_event_head);
		TAILQ_REMOVE(&fehead, fe, fe_link);
		DPRINTF_FPX_EVENT("reusing", fe);
	} else {
		/* add a new element to the list */
		fe = zalloc_permanent_type(struct fpx_event);
	}
	memcpy(fe->fe_uuid, uuid, sizeof(uuid_t));
	fe->fe_code = code;
	fe->fe_xcpt = xcpt;
	TAILQ_INSERT_HEAD(&fehead, fe, fe_link);
	lck_mtx_unlock(&fpxlock);

	DPRINTF_FPX_EVENT("novel", fe);

	return true;
}

void
fpxlog(
	int code,       /* Mach exception code: e.g. 5 or 8 */
	uint32_t stat,  /* Full FP status register bits */
	uint32_t ctrl,  /* Full FP control register bits */
	uint32_t xcpt)  /* Exception bits from FP status */
{
	proc_t p = current_proc();
	if (PROC_NULL == p) {
		return;
	}

	uuid_t uuid;
	proc_getexecutableuuid(p, uuid, sizeof(uuid));

	/*
	 * Check to see if an exception with this <uuid, code, xcpt>
	 * has been seen before.  If "novel" then log a message.
	 */
	if (!novel_fpx_event(uuid, code, xcpt)) {
		return;
	}

	const size_t nmlen = 2 * MAXCOMLEN + 1;
	char nm[nmlen] = {};
	proc_selfname(nm, nmlen);
	if (escape_str(nm, strlen(nm) + 1, nmlen)) {
		snprintf(nm, nmlen, "(a.out)");
	}

	const size_t slen = 8 + 1 + 8 + 1;
	char xcptstr[slen], csrstr[slen];

	snprintf(xcptstr, slen, "%x.%x", code, xcpt);
	if (ctrl == stat) {
		snprintf(csrstr, slen, "%x", ctrl);
	} else {
		snprintf(csrstr, slen, "%x.%x", ctrl, stat);
	}

#if DEVELOPMENT || DEBUG
	printf("%s[%d]: com.apple.kernel.fpx: %s, %s\n",
	    nm, proc_pid(p), xcptstr, csrstr);
#endif
	kern_asl_msg(LOG_DEBUG, "messagetracer", 5,
	    /* 0 */ "com.apple.message.domain", "com.apple.kernel.fpx",
	    /* 1 */ "com.apple.message.signature", nm,
	    /* 2 */ "com.apple.message.signature2", xcptstr,
	    /* 3 */ "com.apple.message.value", csrstr,
	    /* 4 */ "com.apple.message.summarize", "YES",
	    NULL);
}

#else

void
fpxlog_init(void)
{
}

#endif /* __x86_64__ */
