// vim:noexpandtab
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/ulock.h>

#include "turnstile_multihop_types.h"

typedef _Atomic(u32) lock_t;

__inline static void
yield(void)
{
#if !defined(__x86_64__) && !defined(__i386__)
	__asm volatile ("yield");
#else
	__asm volatile ("pause");
#endif
}

__inline static void
wfe(void)
{
#if !defined(__x86_64__) && !defined(__i386__)
	__asm volatile ("wfe");
#else
	__asm volatile ("pause");
#endif
}

__inline static void
wfi(void)
{
#if !defined(__x86_64__) && !defined(__i386__)
	__asm volatile ("wfi");
#else
	__asm volatile ("pause");
#endif
}

__inline static void
sev(void)
{
#if !defined(__x86_64__) && !defined(__i386__)
	__asm volatile ("sev");
#endif
}

#include <os/tsd.h>

#ifndef __TSD_MACH_THREAD_SELF
#define __TSD_MACH_THREAD_SELF 3
#endif

__inline static mach_port_name_t
_os_get_self(void)
{
	mach_port_name_t self = (mach_port_name_t)(uintptr_t)(void *)_os_tsd_get_direct(__TSD_MACH_THREAD_SELF);
	return self;
}

#define ULL_WAITERS     1U

static uint32_t lock_no_wait[4] = { 0, 0, 0, 0};
static uint32_t lock_wait[4] = { 0, 0, 0, 0};

static mach_port_name_t main_thread_name = 0;

__inline static void
ull_lock(lock_t *lock, int id, uint opcode, uint flags)
{
	u32 thread_id = _os_get_self() & ~0x3u;
	u32 ull_locked = (opcode == UL_UNFAIR_LOCK) ? thread_id : 4u;
	u32 mach_id = _os_get_self() >> 2;
	u32 prev;
	bool succeeded = false;
	bool waiters = false;
	bool called_wait = false;
	u32 count = 0;

	do {
		count++;
		if ((count % 100000) == 0) {
			printf("[%d,%d]%s>top of loop count=%d\n", id, mach_id, __FUNCTION__, count);
		}
		u32 new = waiters ? (ULL_WAITERS | ull_locked) : ull_locked;
		prev = 0;
		__c11_atomic_compare_exchange_strong(lock, &prev, new, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
		if (prev == 0) {
			/* Was unlocked, now locked */
			succeeded = true;
			break;
		}

		u32 value = prev;
		if (!(value & ULL_WAITERS)) {
			new = value | ULL_WAITERS;
			__c11_atomic_compare_exchange_strong(lock, &prev, new, __ATOMIC_RELAXED, __ATOMIC_RELAXED);
			if (prev == value) {
				/* succeeded in setting ULL_WAITERS */
				value = new;
			} else if (prev & ULL_WAITERS) {
				/* Didn't succeed, but someone else already set ULL_WAITERS */
				value = prev;
			} else {
				/* Something changed under us, so try again */
				if (count % 100000 == 0) {
					printf("[%d,%d]%s>Something changed under us, prev=%d\n", id, mach_id, __FUNCTION__, prev);
				}
				continue;
			}
		}
		/* Locked with waiters indication, so block */
		int ret = __ulock_wait(flags | opcode, lock, value, 0);
		called_wait = true;
		if (ret < 0) {
			if (flags & ULF_NO_ERRNO) {
				errno = -ret;
			}
			if (errno == EFAULT) {
				continue;
			}
			printf("[%d,%d]%s>ull_wait() error: %s\n", id, mach_id, __FUNCTION__, strerror(errno));
			exit(1);
		}
		waiters = (ret > 0);

		if (count % 100000 == 0) {
			printf("[%d,%d]%s>bottom of loop prev=%d\n", id, mach_id, __FUNCTION__, prev);
		}
	} while (!succeeded);

	if (called_wait) {
		lock_wait[id]++;
	} else {
		lock_no_wait[id]++;
	}
}

static uint32_t unlock_no_waiters[4] = { 0, 0, 0, 0};
static uint32_t unlock_waiters[4] =  { 0, 0, 0, 0 };
static uint32_t unlock_waiters_gone[4] =  { 0, 0, 0, 0 };
static uint32_t unlock_waiters_wake_thread[4] =  { 0, 0, 0, 0 };

__inline static void
ull_unlock(lock_t *lock, int id, uint opcode, uint flags)
{
	u32 thread_id = _os_get_self() & ~0x3u;
	u32 ull_locked = (opcode == UL_UNFAIR_LOCK) ? thread_id : 4u;
	u32 mach_id = _os_get_self() >> 2;
	u32 prev = ull_locked;
	__c11_atomic_compare_exchange_strong(lock, &prev, 0, __ATOMIC_RELEASE, __ATOMIC_RELAXED);
	if (prev == ull_locked) {
		unlock_no_waiters[id]++;
		return;
	}

	if (prev == 0) {
		printf("%s>already unlocked\n", __FUNCTION__);
		exit(1);
	}

	if (prev == (ULL_WAITERS | ull_locked)) {
		/* locked with waiters */
		*lock = 0;
		__c11_atomic_thread_fence(__ATOMIC_ACQ_REL);

		if ((flags & ULF_WAKE_THREAD) && (_os_get_self() == main_thread_name)) {
			flags &= ~(uint)ULF_WAKE_THREAD;
		}
		int ret = __ulock_wake((flags | opcode), lock, main_thread_name);
		if ((ret < 0) && (flags & ULF_NO_ERRNO)) {
			errno = -ret;
		}
		if ((flags & ULF_WAKE_THREAD) && (ret < 0) && (errno == EALREADY)) {
			flags &= ~(uint)ULF_WAKE_THREAD;
			ret = __ulock_wake((flags | opcode), lock, 0);
			if ((ret < 0) && (flags & ULF_NO_ERRNO)) {
				errno = -ret;
			}
		} else if ((flags & ULF_WAKE_THREAD) && (ret == 0)) {
			unlock_waiters_wake_thread[id]++;
		}
		if (ret < 0) {
			if (errno == ENOENT) {
				unlock_waiters_gone[id]++;
			} else {
				printf("[%d,%d]%s>ull_wake() error: %s\n", id, mach_id, __FUNCTION__, strerror(errno));
				exit(1);
			}
		}
		unlock_waiters[id]++;
	} else {
		printf("%s>unexpected lock value %d\n", __FUNCTION__, prev);
		exit(1);
	}
}
