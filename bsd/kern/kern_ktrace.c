/*
 * Copyright (c) 2015 Apple Inc. All rights reserved.
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

/*
 * This file manages the ownership of ktrace and its subsystems, like kdebug
 * and kperf, as well as the overall state of the system, whether it is in
 * foreground or background mode.
 *
 * When unconfigured or in background mode, any root process can take ownership
 * of ktrace and configure it, changing the state to foreground and, in the case
 * of a transition out of background, resetting the background configuration.
 *
 * When in foreground mode, if the owning process is still running, only it may
 * configure ktrace.  If it exits, ktrace keeps running but any root process can
 * change the configuration.  When ktrace is reset, the state changes back to
 * unconfigured and a notification is sent on the ktrace_background host special
 * port.
 *
 * If a process has set itself as the background tool, using the init_background
 * sysctl, it can configure ktrace only when ktrace is off or already in
 * background mode.  The first attempt to configure ktrace by the background pid
 * when it is off results in the transition to background mode.
 */

#include <sys/ktrace.h>

#include <mach/host_priv.h>
#include <mach/mach_types.h>
#include <mach/ktrace_background.h>

#include <sys/kauth.h>
#include <sys/priv.h>
#include <sys/proc.h>
char *proc_name_address(void *p);
#include <sys/sysctl.h>
#include <sys/vm.h>

#include <kern/locks.h>
#include <kern/assert.h>

#include <sys/kdebug.h>
#include <kperf/kperf.h>

#include <kern/host.h>

kern_return_t ktrace_background_available_notify_user(void);

lck_mtx_t *ktrace_lock;

/*
 * The overall state of ktrace, whether it is unconfigured, in foreground mode,
 * or in background mode.  The state determines which processes can configure
 * ktrace.
 */
static enum ktrace_state ktrace_state = KTRACE_STATE_OFF;

/* The true owner of ktrace, checked by ktrace_access_check(). */
static uint64_t ktrace_owning_unique_id = 0;
static pid_t ktrace_owning_pid = 0;

/*
 * The background pid of ktrace, automatically made the owner when
 * transitioning to background mode.
 */
static uint64_t ktrace_bg_unique_id = 0;
static pid_t ktrace_bg_pid = 0;

/* The name of the last process to configure ktrace. */
static char ktrace_last_owner_execname[MAXCOMLEN + 1] = { 0 };

/*
 * Which subsystems of ktrace (currently kdebug and kperf) are active.
 */
static uint32_t ktrace_active_mask = 0;

/*
 * At boot or when a daemon has been newly loaded, it's necessary to bootstrap
 * user space background tools by sending a background available notification
 * when the init_background sysctl is made.
 *
 * Background tools must be RunAtLoad daemons.
 */
static boolean_t should_notify_on_init = TRUE;

/* Set the owning process of ktrace. */
static void ktrace_set_owning_proc(proc_t p);

/* Reset ktrace ownership back to unowned. */
static void ktrace_release_ownership(void);

/* Make the background tool the owner of ktrace. */
static void ktrace_promote_background(void);

/*
 * If user space sets a pid manually (through kperf "blessing"), ktrace should
 * not treat resets as releasing ownership.  At that point, ownership is only
 * released when the owner is set to an invalid pid.
 *
 * This is managed by the user space-oriented function ktrace_set_owning_pid
 * and ktrace_unset_owning_pid.
 */
boolean_t ktrace_keep_ownership_on_reset = FALSE;

/* Allow user space to unset the owning pid and potentially reset ktrace. */
static void ktrace_set_invalid_owning_pid(void);

/*
 * This flag allows any root process to set a new ktrace owner.  It is
 * currently used by Instruments.
 */
int ktrace_root_set_owner_allowed = 0;

static void
ktrace_reset_internal(uint32_t reset_mask)
{
	if (!ktrace_keep_ownership_on_reset) {
		ktrace_active_mask &= ~reset_mask;
	}

	if (reset_mask & KTRACE_KPERF) {
		kperf_reset();
	}
	if (reset_mask & KTRACE_KDEBUG) {
		kdebug_reset();
	}

	if (ktrace_active_mask == 0) {
		if (ktrace_state == KTRACE_STATE_FG) {
			/* transition from foreground to background */
			ktrace_promote_background();
		} else if (ktrace_state == KTRACE_STATE_BG) {
			/* background tool is resetting ktrace */
			should_notify_on_init = TRUE;
			ktrace_release_ownership();
			ktrace_state = KTRACE_STATE_OFF;
		}
	}
}

void
ktrace_reset(uint32_t reset_mask)
{
	lck_mtx_assert(ktrace_lock, LCK_MTX_ASSERT_OWNED);

	if (ktrace_active_mask == 0) {
		if (!ktrace_keep_ownership_on_reset) {
			assert(ktrace_state == KTRACE_STATE_OFF);
		}
		return;
	}

	ktrace_reset_internal(reset_mask);
}

static void
ktrace_promote_background(void)
{
	lck_mtx_assert(ktrace_lock, LCK_MTX_ASSERT_OWNED);
	assert(ktrace_state != KTRACE_STATE_BG);

	/*
	 * Remember to send a background available notification on the next init
	 * if the notification failed (meaning no task holds the receive right
	 * for the host special port).
	 */
	if (ktrace_background_available_notify_user() == KERN_FAILURE) {
		should_notify_on_init = TRUE;
	} else {
		should_notify_on_init = FALSE;
	}

	ktrace_release_ownership();
	ktrace_state = KTRACE_STATE_OFF;
}

bool
ktrace_background_active(void)
{
	lck_mtx_assert(ktrace_lock, LCK_MTX_ASSERT_OWNED);
	return (ktrace_state == KTRACE_STATE_BG);
}

int
ktrace_read_check(void)
{
	lck_mtx_assert(ktrace_lock, LCK_MTX_ASSERT_OWNED);

	if (proc_uniqueid(current_proc()) == ktrace_owning_unique_id)
	{
		return 0;
	}

	return kauth_cred_issuser(kauth_cred_get()) ? 0 : EPERM;
}

/* If an owning process has exited, reset the ownership. */
static void
ktrace_ownership_maintenance(void)
{
	lck_mtx_assert(ktrace_lock, LCK_MTX_ASSERT_OWNED);

	/* do nothing if ktrace is not owned */
	if (ktrace_owning_unique_id == 0) {
		return;
	}

	/* reset ownership if process cannot be found */

	proc_t owning_proc = proc_find(ktrace_owning_pid);

	if (owning_proc != NULL) {
		/* make sure the pid was not recycled */
		if (proc_uniqueid(owning_proc) != ktrace_owning_unique_id) {
			ktrace_release_ownership();
		}

		proc_rele(owning_proc);
	} else {
		ktrace_release_ownership();
	}
}

int
ktrace_configure(uint32_t config_mask)
{
	lck_mtx_assert(ktrace_lock, LCK_MTX_ASSERT_OWNED);
	assert(config_mask != 0);

	proc_t p = current_proc();

	/* if process clearly owns ktrace, allow */
	if (proc_uniqueid(p) == ktrace_owning_unique_id) {
		ktrace_active_mask |= config_mask;
		return 0;
	}

	/* background configure while foreground is active is not allowed */
	if (proc_uniqueid(p) == ktrace_bg_unique_id &&
	    ktrace_state == KTRACE_STATE_FG)
	{
		return EBUSY;
	}

	ktrace_ownership_maintenance();

	/* allow process to gain control when unowned or background */
	if (ktrace_owning_unique_id == 0 || ktrace_state == KTRACE_STATE_BG) {
		if (!kauth_cred_issuser(kauth_cred_get())) {
			return EPERM;
		}

		ktrace_set_owning_proc(p);
		ktrace_active_mask |= config_mask;
		return 0;
	}

	/* owned by an existing, different process */
	return EBUSY;
}

void
ktrace_disable(enum ktrace_state state_to_match)
{
	if (ktrace_state == state_to_match) {
		kernel_debug_disable();
		kperf_sampling_disable();
	}
}

int
ktrace_get_owning_pid(void)
{
	lck_mtx_assert(ktrace_lock, LCK_MTX_ASSERT_OWNED);

	ktrace_ownership_maintenance();
	return ktrace_owning_pid;
}

void
ktrace_kernel_configure(uint32_t config_mask)
{
	lck_mtx_assert(ktrace_lock, LCK_MTX_ASSERT_OWNED);

	if (ktrace_state != KTRACE_STATE_OFF) {
		if (ktrace_active_mask & KTRACE_KPERF) {
			kperf_reset();
		}
		if (ktrace_active_mask & KTRACE_KDEBUG) {
			kdebug_reset();
		}
	}

	ktrace_active_mask = config_mask;
	ktrace_state = KTRACE_STATE_FG;

	ktrace_release_ownership();
	strlcpy(ktrace_last_owner_execname, "kernel_task",
		sizeof(ktrace_last_owner_execname));
}

static errno_t
ktrace_init_background(void)
{
	int err = 0;

	lck_mtx_assert(ktrace_lock, LCK_MTX_ASSERT_OWNED);

	if ((err = priv_check_cred(kauth_cred_get(), PRIV_KTRACE_BACKGROUND, 0))) {
		return err;
	}

	/*
	 * When a background tool first checks in, send a notification if ktrace
	 * is available.
	 */
	if (should_notify_on_init) {
		if (ktrace_state == KTRACE_STATE_OFF) {
			/*
			 * This notification can only fail if a process does not
			 * hold the receive right for the host special port.
			 * Return an error and don't make the current process
			 * the background tool.
			 */
			if (ktrace_background_available_notify_user() == KERN_FAILURE) {
				return EINVAL;
			}
		}
		should_notify_on_init = FALSE;
	}

	proc_t p = current_proc();

	ktrace_bg_unique_id = proc_uniqueid(p);
	ktrace_bg_pid = proc_pid(p);

	if (ktrace_state == KTRACE_STATE_BG) {
		ktrace_set_owning_proc(p);
	}

	return 0;
}

void
ktrace_set_invalid_owning_pid(void)
{
	if (ktrace_keep_ownership_on_reset) {
		ktrace_keep_ownership_on_reset = FALSE;
		ktrace_reset_internal(ktrace_active_mask);
	}
}

int
ktrace_set_owning_pid(int pid)
{
	lck_mtx_assert(ktrace_lock, LCK_MTX_ASSERT_OWNED);

	/* allow user space to successfully unset owning pid */
	if (pid == -1) {
		ktrace_set_invalid_owning_pid();
		return 0;
	}

	/* use ktrace_reset or ktrace_release_ownership, not this */
	if (pid == 0) {
		ktrace_set_invalid_owning_pid();
		return EINVAL;
	}

	proc_t p = proc_find(pid);
	if (!p) {
		ktrace_set_invalid_owning_pid();
		return ESRCH;
	}

	ktrace_keep_ownership_on_reset = TRUE;
	ktrace_set_owning_proc(p);

	proc_rele(p);
	return 0;
}

static void
ktrace_set_owning_proc(proc_t p)
{
	lck_mtx_assert(ktrace_lock, LCK_MTX_ASSERT_OWNED);
	assert(p);

	if (ktrace_state != KTRACE_STATE_FG) {
		if (proc_uniqueid(p) == ktrace_bg_unique_id) {
			ktrace_state = KTRACE_STATE_BG;
		} else {
			if (ktrace_state == KTRACE_STATE_BG) {
				if (ktrace_active_mask & KTRACE_KPERF) {
					kperf_reset();
				}
				if (ktrace_active_mask & KTRACE_KDEBUG) {
					kdebug_reset();
				}

				ktrace_active_mask = 0;
			}
			ktrace_state = KTRACE_STATE_FG;
			should_notify_on_init = FALSE;
		}
	}

	ktrace_owning_unique_id = proc_uniqueid(p);
	ktrace_owning_pid = proc_pid(p);
	strlcpy(ktrace_last_owner_execname, proc_name_address(p),
		sizeof(ktrace_last_owner_execname));
}

static void
ktrace_release_ownership(void)
{
	lck_mtx_assert(ktrace_lock, LCK_MTX_ASSERT_OWNED);

	ktrace_owning_unique_id = 0;
	ktrace_owning_pid = 0;
}

#define SYSCTL_INIT_BACKGROUND (1)

static int ktrace_sysctl SYSCTL_HANDLER_ARGS;

SYSCTL_NODE(, OID_AUTO, ktrace, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "ktrace");

SYSCTL_UINT(_ktrace, OID_AUTO, state, CTLFLAG_RD | CTLFLAG_LOCKED,
            &ktrace_state, 0,
            "");

SYSCTL_INT(_ktrace, OID_AUTO, owning_pid, CTLFLAG_RD | CTLFLAG_LOCKED,
           &ktrace_owning_pid, 0,
           "pid of the process that owns ktrace");

SYSCTL_INT(_ktrace, OID_AUTO, background_pid, CTLFLAG_RD | CTLFLAG_LOCKED,
           &ktrace_bg_pid, 0,
           "pid of the background ktrace tool");

SYSCTL_STRING(_ktrace, OID_AUTO, configured_by, CTLFLAG_RD | CTLFLAG_LOCKED,
              ktrace_last_owner_execname, 0,
              "execname of process that last configured ktrace");

SYSCTL_PROC(_ktrace, OID_AUTO, init_background, CTLFLAG_RW | CTLFLAG_LOCKED,
            (void *)SYSCTL_INIT_BACKGROUND, sizeof(int),
            ktrace_sysctl, "I", "initialize calling process as background");

static int
ktrace_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg2)
	int ret = 0;
	uintptr_t type = (uintptr_t)arg1;

	lck_mtx_lock(ktrace_lock);

	if (!kauth_cred_issuser(kauth_cred_get())) {
		ret = EPERM;
		goto out;
	}

	if (type == SYSCTL_INIT_BACKGROUND) {
		if (req->newptr != USER_ADDR_NULL) {
			ret = ktrace_init_background();
			goto out;
		} else {
			ret = EINVAL;
			goto out;
		}
	} else {
		ret = EINVAL;
		goto out;
	}

out:
	lck_mtx_unlock(ktrace_lock);
	return ret;
}

/* This should only be called from the bootstrap thread. */
void
ktrace_init(void)
{
	static lck_grp_attr_t *lock_grp_attr = NULL;
	static lck_grp_t *lock_grp = NULL;
	static boolean_t initialized = FALSE;

	if (initialized) {
		return;
	}

	lock_grp_attr = lck_grp_attr_alloc_init();
	lock_grp = lck_grp_alloc_init("ktrace", lock_grp_attr);
	lck_grp_attr_free(lock_grp_attr);

	ktrace_lock = lck_mtx_alloc_init(lock_grp, LCK_ATTR_NULL);
	assert(ktrace_lock);
	initialized = TRUE;
}
