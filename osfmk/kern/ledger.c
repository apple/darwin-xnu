/*
 * Copyright (c) 2010-2018 Apple Computer, Inc. All rights reserved.
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
 * @OSF_COPYRIGHT@
 */

#include <kern/kern_types.h>
#include <kern/ledger.h>
#include <kern/kalloc.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/coalition.h>

#include <kern/processor.h>
#include <kern/machine.h>
#include <kern/queue.h>
#include <kern/policy_internal.h>

#include <sys/errno.h>

#include <libkern/OSAtomic.h>
#include <mach/mach_types.h>
#include <os/overflow.h>

#include <vm/pmap.h>

/*
 * Ledger entry flags. Bits in second nibble (masked by 0xF0) are used for
 * ledger actions (LEDGER_ACTION_BLOCK, etc).
 */
#define LF_ENTRY_ACTIVE         0x0001  /* entry is active if set */
#define LF_WAKE_NEEDED          0x0100  /* one or more threads are asleep */
#define LF_WAKE_INPROGRESS      0x0200  /* the wait queue is being processed */
#define LF_REFILL_SCHEDULED     0x0400  /* a refill timer has been set */
#define LF_REFILL_INPROGRESS    0x0800  /* the ledger is being refilled */
#define LF_CALLED_BACK          0x1000  /* callback was called for balance in deficit */
#define LF_WARNED               0x2000  /* callback was called for balance warning */
#define LF_TRACKING_MAX         0x4000  /* track max balance. Exclusive w.r.t refill */
#define LF_PANIC_ON_NEGATIVE    0x8000  /* panic if it goes negative */
#define LF_TRACK_CREDIT_ONLY    0x10000 /* only update "credit" */

/* Determine whether a ledger entry exists and has been initialized and active */
#define ENTRY_VALID(l, e)                                       \
	(((l) != NULL) && ((e) >= 0) && ((e) < (l)->l_size) &&  \
	(((l)->l_entries[e].le_flags & LF_ENTRY_ACTIVE) == LF_ENTRY_ACTIVE))

#define ASSERT(a) assert(a)

#ifdef LEDGER_DEBUG
int ledger_debug = 0;

#define lprintf(a) if (ledger_debug) {                                  \
	printf("%lld  ", abstime_to_nsecs(mach_absolute_time() / 1000000)); \
	printf a ;                                                      \
}
#else
#define lprintf(a)
#endif

struct ledger_callback {
	ledger_callback_t       lc_func;
	const void              *lc_param0;
	const void              *lc_param1;
};

struct entry_template {
	char                    et_key[LEDGER_NAME_MAX];
	char                    et_group[LEDGER_NAME_MAX];
	char                    et_units[LEDGER_NAME_MAX];
	uint32_t                et_flags;
	struct ledger_callback  *et_callback;
};

lck_grp_t ledger_lck_grp;
os_refgrp_decl(static, ledger_refgrp, "ledger", NULL);

/*
 * Modifying the reference count, table size, or table contents requires
 * holding the lt_lock.  Modfying the table address requires both lt_lock
 * and setting the inuse bit.  This means that the lt_entries field can be
 * safely dereferenced if you hold either the lock or the inuse bit.  The
 * inuse bit exists solely to allow us to swap in a new, larger entries
 * table without requiring a full lock to be acquired on each lookup.
 * Accordingly, the inuse bit should never be held for longer than it takes
 * to extract a value from the table - i.e., 2 or 3 memory references.
 */
struct ledger_template {
	const char              *lt_name;
	int                     lt_refs;
	int                     lt_cnt;
	int                     lt_table_size;
	volatile uint32_t       lt_inuse;
	lck_mtx_t               lt_lock;
	zone_t                  lt_zone;
	bool                    lt_initialized;
	struct entry_template   *lt_entries;
};

#define template_lock(template)         lck_mtx_lock(&(template)->lt_lock)
#define template_unlock(template)       lck_mtx_unlock(&(template)->lt_lock)

#define TEMPLATE_INUSE(s, t) {                                  \
	s = splsched();                                         \
	while (OSCompareAndSwap(0, 1, &((t)->lt_inuse)))        \
	        ;                                               \
}

#define TEMPLATE_IDLE(s, t) {                                   \
	(t)->lt_inuse = 0;                                      \
	splx(s);                                                \
}

static int ledger_cnt = 0;
/* ledger ast helper functions */
static uint32_t ledger_check_needblock(ledger_t l, uint64_t now);
static kern_return_t ledger_perform_blocking(ledger_t l);
static uint32_t flag_set(volatile uint32_t *flags, uint32_t bit);
static uint32_t flag_clear(volatile uint32_t *flags, uint32_t bit);

static void ledger_entry_check_new_balance(thread_t thread, ledger_t ledger,
    int entry, struct ledger_entry *le);

#if 0
static void
debug_callback(const void *p0, __unused const void *p1)
{
	printf("ledger: resource exhausted [%s] for task %p\n",
	    (const char *)p0, p1);
}
#endif

/************************************/

static uint64_t
abstime_to_nsecs(uint64_t abstime)
{
	uint64_t nsecs;

	absolutetime_to_nanoseconds(abstime, &nsecs);
	return nsecs;
}

static uint64_t
nsecs_to_abstime(uint64_t nsecs)
{
	uint64_t abstime;

	nanoseconds_to_absolutetime(nsecs, &abstime);
	return abstime;
}

void
ledger_init(void)
{
	lck_grp_init(&ledger_lck_grp, "ledger", LCK_GRP_ATTR_NULL);
}

ledger_template_t
ledger_template_create(const char *name)
{
	ledger_template_t template;

	template = (ledger_template_t)kalloc(sizeof(*template));
	if (template == NULL) {
		return NULL;
	}

	template->lt_name = name;
	template->lt_refs = 1;
	template->lt_cnt = 0;
	template->lt_table_size = 1;
	template->lt_inuse = 0;
	template->lt_zone = NULL;
	lck_mtx_init(&template->lt_lock, &ledger_lck_grp, LCK_ATTR_NULL);

	template->lt_entries = (struct entry_template *)
	    kalloc(sizeof(struct entry_template) * template->lt_table_size);
	if (template->lt_entries == NULL) {
		kfree(template, sizeof(*template));
		template = NULL;
	}

	return template;
}

ledger_template_t
ledger_template_copy(ledger_template_t template, const char *name)
{
	struct entry_template * new_entries = NULL;
	ledger_template_t new_template = ledger_template_create(name);

	if (new_template == NULL) {
		return new_template;
	}

	template_lock(template);
	assert(template->lt_initialized);

	new_entries = (struct entry_template *)
	    kalloc(sizeof(struct entry_template) * template->lt_table_size);

	if (new_entries) {
		/* Copy the template entries. */
		bcopy(template->lt_entries, new_entries, sizeof(struct entry_template) * template->lt_table_size);
		kfree(new_template->lt_entries, sizeof(struct entry_template) * new_template->lt_table_size);

		new_template->lt_entries = new_entries;
		new_template->lt_table_size = template->lt_table_size;
		new_template->lt_cnt = template->lt_cnt;
	} else {
		/* Tear down the new template; we've failed. :( */
		ledger_template_dereference(new_template);
		new_template = NULL;
	}

	template_unlock(template);

	return new_template;
}

void
ledger_template_dereference(ledger_template_t template)
{
	template_lock(template);
	template->lt_refs--;
	template_unlock(template);

	if (template->lt_refs == 0) {
		kfree(template->lt_entries, sizeof(struct entry_template) * template->lt_table_size);
		lck_mtx_destroy(&template->lt_lock, &ledger_lck_grp);
		kfree(template, sizeof(*template));
	}
}

/*
 * Add a new entry to the list of entries in a ledger template. There is
 * currently no mechanism to remove an entry.  Implementing such a mechanism
 * would require us to maintain per-entry reference counts, which we would
 * prefer to avoid if possible.
 */
int
ledger_entry_add(ledger_template_t template, const char *key,
    const char *group, const char *units)
{
	int idx;
	struct entry_template *et;

	if ((key == NULL) || (strlen(key) >= LEDGER_NAME_MAX) || (template->lt_zone != NULL)) {
		return -1;
	}

	template_lock(template);

	/* If the table is full, attempt to double its size */
	if (template->lt_cnt == template->lt_table_size) {
		struct entry_template *new_entries, *old_entries;
		int old_cnt, old_sz, new_sz = 0;
		spl_t s;

		old_cnt = template->lt_table_size;
		old_sz = old_cnt * (int)(sizeof(struct entry_template));
		/* double old_sz allocation, but check for overflow */
		if (os_mul_overflow(old_sz, 2, &new_sz)) {
			template_unlock(template);
			return -1;
		}
		new_entries = kalloc(new_sz);
		if (new_entries == NULL) {
			template_unlock(template);
			return -1;
		}
		memcpy(new_entries, template->lt_entries, old_sz);
		memset(((char *)new_entries) + old_sz, 0, old_sz);
		/* assume: if the sz didn't overflow, neither will the count */
		template->lt_table_size = old_cnt * 2;

		old_entries = template->lt_entries;

		TEMPLATE_INUSE(s, template);
		template->lt_entries = new_entries;
		TEMPLATE_IDLE(s, template);

		kfree(old_entries, old_sz);
	}

	et = &template->lt_entries[template->lt_cnt];
	strlcpy(et->et_key, key, LEDGER_NAME_MAX);
	strlcpy(et->et_group, group, LEDGER_NAME_MAX);
	strlcpy(et->et_units, units, LEDGER_NAME_MAX);
	et->et_flags = LF_ENTRY_ACTIVE;
	et->et_callback = NULL;

	idx = template->lt_cnt++;
	template_unlock(template);

	return idx;
}


kern_return_t
ledger_entry_setactive(ledger_t ledger, int entry)
{
	struct ledger_entry *le;

	if ((ledger == NULL) || (entry < 0) || (entry >= ledger->l_size)) {
		return KERN_INVALID_ARGUMENT;
	}

	le = &ledger->l_entries[entry];
	if ((le->le_flags & LF_ENTRY_ACTIVE) == 0) {
		flag_set(&le->le_flags, LF_ENTRY_ACTIVE);
	}
	return KERN_SUCCESS;
}


int
ledger_key_lookup(ledger_template_t template, const char *key)
{
	int idx;

	template_lock(template);
	for (idx = 0; idx < template->lt_cnt; idx++) {
		if (template->lt_entries != NULL &&
		    (strcmp(key, template->lt_entries[idx].et_key) == 0)) {
			break;
		}
	}

	if (idx >= template->lt_cnt) {
		idx = -1;
	}
	template_unlock(template);

	return idx;
}

/*
 * Complete the initialization of ledger template
 * by initializing ledger zone. After initializing
 * the ledger zone, adding an entry in the ledger
 * template would fail.
 */
void
ledger_template_complete(ledger_template_t template)
{
	size_t ledger_size;
	ledger_size = sizeof(struct ledger) + (template->lt_cnt * sizeof(struct ledger_entry));
	template->lt_zone = zinit(ledger_size, CONFIG_TASK_MAX * ledger_size,
	    ledger_size,
	    template->lt_name);
	template->lt_initialized = true;
}

/*
 * Like ledger_template_complete, except we'll ask
 * the pmap layer to manage allocations for us.
 * Meant for ledgers that should be owned by the
 * pmap layer.
 */
void
ledger_template_complete_secure_alloc(ledger_template_t template)
{
	size_t ledger_size;
	ledger_size = sizeof(struct ledger) + (template->lt_cnt * sizeof(struct ledger_entry));
	pmap_ledger_alloc_init(ledger_size);
	template->lt_initialized = true;
}

/*
 * Create a new ledger based on the specified template.  As part of the
 * ledger creation we need to allocate space for a table of ledger entries.
 * The size of the table is based on the size of the template at the time
 * the ledger is created.  If additional entries are added to the template
 * after the ledger is created, they will not be tracked in this ledger.
 */
ledger_t
ledger_instantiate(ledger_template_t template, int entry_type)
{
	ledger_t ledger;
	size_t cnt;
	int i;

	template_lock(template);
	template->lt_refs++;
	cnt = template->lt_cnt;
	template_unlock(template);

	if (template->lt_zone) {
		ledger = (ledger_t)zalloc(template->lt_zone);
	} else {
		ledger = pmap_ledger_alloc();
	}

	if (ledger == NULL) {
		ledger_template_dereference(template);
		return LEDGER_NULL;
	}

	ledger->l_template = template;
	ledger->l_id = ledger_cnt++;
	os_ref_init(&ledger->l_refs, &ledger_refgrp);
	ledger->l_size = (int32_t)cnt;

	template_lock(template);
	assert(ledger->l_size <= template->lt_cnt);
	for (i = 0; i < ledger->l_size; i++) {
		struct ledger_entry *le = &ledger->l_entries[i];
		struct entry_template *et = &template->lt_entries[i];

		le->le_flags = et->et_flags;
		/* make entry inactive by removing  active bit */
		if (entry_type == LEDGER_CREATE_INACTIVE_ENTRIES) {
			flag_clear(&le->le_flags, LF_ENTRY_ACTIVE);
		}
		/*
		 * If template has a callback, this entry is opted-in,
		 * by default.
		 */
		if (et->et_callback != NULL) {
			flag_set(&le->le_flags, LEDGER_ACTION_CALLBACK);
		}
		le->le_credit        = 0;
		le->le_debit         = 0;
		le->le_limit         = LEDGER_LIMIT_INFINITY;
		le->le_warn_percent  = LEDGER_PERCENT_NONE;
		le->_le.le_refill.le_refill_period = 0;
		le->_le.le_refill.le_last_refill   = 0;
	}
	template_unlock(template);

	return ledger;
}

static uint32_t
flag_set(volatile uint32_t *flags, uint32_t bit)
{
	return OSBitOrAtomic(bit, flags);
}

static uint32_t
flag_clear(volatile uint32_t *flags, uint32_t bit)
{
	return OSBitAndAtomic(~bit, flags);
}

/*
 * Take a reference on a ledger
 */
void
ledger_reference(ledger_t ledger)
{
	if (!LEDGER_VALID(ledger)) {
		return;
	}

	os_ref_retain(&ledger->l_refs);
}

/*
 * Remove a reference on a ledger.  If this is the last reference,
 * deallocate the unused ledger.
 */
void
ledger_dereference(ledger_t ledger)
{
	if (!LEDGER_VALID(ledger)) {
		return;
	}

	if (os_ref_release(&ledger->l_refs) == 0) {
		if (ledger->l_template->lt_zone) {
			zfree(ledger->l_template->lt_zone, ledger);
		} else {
			pmap_ledger_free(ledger);
		}
	}
}

/*
 * Determine whether an entry has exceeded its warning level.
 */
static inline int
warn_level_exceeded(struct ledger_entry *le)
{
	ledger_amount_t balance;

	if (le->le_flags & LF_TRACK_CREDIT_ONLY) {
		assert(le->le_debit == 0);
	} else {
		assert((le->le_credit >= 0) && (le->le_debit >= 0));
	}

	/*
	 * XXX - Currently, we only support warnings for ledgers which
	 * use positive limits.
	 */
	balance = le->le_credit - le->le_debit;
	if (le->le_warn_percent != LEDGER_PERCENT_NONE &&
	    ((balance > (le->le_limit * le->le_warn_percent) >> 16))) {
		return 1;
	}
	return 0;
}

/*
 * Determine whether an entry has exceeded its limit.
 */
static inline int
limit_exceeded(struct ledger_entry *le)
{
	ledger_amount_t balance;

	if (le->le_flags & LF_TRACK_CREDIT_ONLY) {
		assert(le->le_debit == 0);
	} else {
		assert((le->le_credit >= 0) && (le->le_debit >= 0));
	}

	balance = le->le_credit - le->le_debit;
	if ((le->le_limit <= 0) && (balance < le->le_limit)) {
		return 1;
	}

	if ((le->le_limit > 0) && (balance > le->le_limit)) {
		return 1;
	}
	return 0;
}

static inline struct ledger_callback *
entry_get_callback(ledger_t ledger, int entry)
{
	struct ledger_callback *callback;
	spl_t s;

	TEMPLATE_INUSE(s, ledger->l_template);
	callback = ledger->l_template->lt_entries[entry].et_callback;
	TEMPLATE_IDLE(s, ledger->l_template);

	return callback;
}

/*
 * If the ledger value is positive, wake up anybody waiting on it.
 */
static inline void
ledger_limit_entry_wakeup(struct ledger_entry *le)
{
	uint32_t flags;

	if (!limit_exceeded(le)) {
		flags = flag_clear(&le->le_flags, LF_CALLED_BACK);

		while (le->le_flags & LF_WAKE_NEEDED) {
			flag_clear(&le->le_flags, LF_WAKE_NEEDED);
			thread_wakeup((event_t)le);
		}
	}
}

/*
 * Refill the coffers.
 */
static void
ledger_refill(uint64_t now, ledger_t ledger, int entry)
{
	uint64_t elapsed, period, periods;
	struct ledger_entry *le;
	ledger_amount_t balance, due;

	assert(entry >= 0 && entry < ledger->l_size);

	le = &ledger->l_entries[entry];

	assert(le->le_limit != LEDGER_LIMIT_INFINITY);

	if (le->le_flags & LF_TRACK_CREDIT_ONLY) {
		assert(le->le_debit == 0);
		return;
	}

	/*
	 * If another thread is handling the refill already, we're not
	 * needed.
	 */
	if (flag_set(&le->le_flags, LF_REFILL_INPROGRESS) & LF_REFILL_INPROGRESS) {
		return;
	}

	/*
	 * If the timestamp we're about to use to refill is older than the
	 * last refill, then someone else has already refilled this ledger
	 * and there's nothing for us to do here.
	 */
	if (now <= le->_le.le_refill.le_last_refill) {
		flag_clear(&le->le_flags, LF_REFILL_INPROGRESS);
		return;
	}

	/*
	 * See how many refill periods have passed since we last
	 * did a refill.
	 */
	period = le->_le.le_refill.le_refill_period;
	elapsed = now - le->_le.le_refill.le_last_refill;
	if ((period == 0) || (elapsed < period)) {
		flag_clear(&le->le_flags, LF_REFILL_INPROGRESS);
		return;
	}

	/*
	 * Optimize for the most common case of only one or two
	 * periods elapsing.
	 */
	periods = 0;
	while ((periods < 2) && (elapsed > 0)) {
		periods++;
		elapsed -= period;
	}

	/*
	 * OK, it's been a long time.  Do a divide to figure out
	 * how long.
	 */
	if (elapsed > 0) {
		periods = (now - le->_le.le_refill.le_last_refill) / period;
	}

	balance = le->le_credit - le->le_debit;
	due = periods * le->le_limit;

	if (balance - due < 0) {
		due = balance;
	}

	assertf(due >= 0, "now=%llu, ledger=%p, entry=%d, balance=%lld, due=%lld", now, ledger, entry, balance, due);

	OSAddAtomic64(due, &le->le_debit);

	assert(le->le_debit >= 0);

	/*
	 * If we've completely refilled the pool, set the refill time to now.
	 * Otherwise set it to the time at which it last should have been
	 * fully refilled.
	 */
	if (balance == due) {
		le->_le.le_refill.le_last_refill = now;
	} else {
		le->_le.le_refill.le_last_refill += (le->_le.le_refill.le_refill_period * periods);
	}

	flag_clear(&le->le_flags, LF_REFILL_INPROGRESS);

	lprintf(("Refill %lld %lld->%lld\n", periods, balance, balance - due));
	if (!limit_exceeded(le)) {
		ledger_limit_entry_wakeup(le);
	}
}

void
ledger_entry_check_new_balance(thread_t thread, ledger_t ledger,
    int entry, struct ledger_entry *le)
{
	if (le->le_flags & LF_TRACKING_MAX) {
		ledger_amount_t balance = le->le_credit - le->le_debit;

		if (balance > le->_le._le_max.le_lifetime_max) {
			le->_le._le_max.le_lifetime_max = balance;
		}

#if CONFIG_LEDGER_INTERVAL_MAX
		if (balance > le->_le._le_max.le_interval_max) {
			le->_le._le_max.le_interval_max = balance;
		}
#endif /* LEDGER_CONFIG_INTERVAL_MAX */
	}

	/* Check to see whether we're due a refill */
	if (le->le_flags & LF_REFILL_SCHEDULED) {
		assert(!(le->le_flags & LF_TRACKING_MAX));

		uint64_t now = mach_absolute_time();
		if ((now - le->_le.le_refill.le_last_refill) > le->_le.le_refill.le_refill_period) {
			ledger_refill(now, ledger, entry);
		}
	}

	if (limit_exceeded(le)) {
		/*
		 * We've exceeded the limit for this entry.  There
		 * are several possible ways to handle it.  We can block,
		 * we can execute a callback, or we can ignore it.  In
		 * either of the first two cases, we want to set the AST
		 * flag so we can take the appropriate action just before
		 * leaving the kernel.  The one caveat is that if we have
		 * already called the callback, we don't want to do it
		 * again until it gets rearmed.
		 */
		if ((le->le_flags & LEDGER_ACTION_BLOCK) ||
		    (!(le->le_flags & LF_CALLED_BACK) &&
		    entry_get_callback(ledger, entry))) {
			act_set_astledger_async(thread);
		}
	} else {
		/*
		 * The balance on the account is below the limit.
		 *
		 * If there are any threads blocked on this entry, now would
		 * be a good time to wake them up.
		 */
		if (le->le_flags & LF_WAKE_NEEDED) {
			ledger_limit_entry_wakeup(le);
		}

		if (le->le_flags & LEDGER_ACTION_CALLBACK) {
			/*
			 * Client has requested that a callback be invoked whenever
			 * the ledger's balance crosses into or out of the warning
			 * level.
			 */
			if (warn_level_exceeded(le)) {
				/*
				 * This ledger's balance is above the warning level.
				 */
				if ((le->le_flags & LF_WARNED) == 0) {
					/*
					 * If we are above the warning level and
					 * have not yet invoked the callback,
					 * set the AST so it can be done before returning
					 * to userland.
					 */
					act_set_astledger_async(thread);
				}
			} else {
				/*
				 * This ledger's balance is below the warning level.
				 */
				if (le->le_flags & LF_WARNED) {
					/*
					 * If we are below the warning level and
					 * the LF_WARNED flag is still set, we need
					 * to invoke the callback to let the client
					 * know the ledger balance is now back below
					 * the warning level.
					 */
					act_set_astledger_async(thread);
				}
			}
		}
	}

	if ((le->le_flags & LF_PANIC_ON_NEGATIVE) &&
	    (le->le_credit < le->le_debit)) {
		panic("ledger_entry_check_new_balance(%p,%d): negative ledger %p credit:%lld debit:%lld balance:%lld\n",
		    ledger, entry, le,
		    le->le_credit,
		    le->le_debit,
		    le->le_credit - le->le_debit);
	}
}

void
ledger_check_new_balance(thread_t thread, ledger_t ledger, int entry)
{
	struct ledger_entry *le;
	assert(entry > 0 && entry <= ledger->l_size);
	le = &ledger->l_entries[entry];
	ledger_entry_check_new_balance(thread, ledger, entry, le);
}

/*
 * Add value to an entry in a ledger for a specific thread.
 */
kern_return_t
ledger_credit_thread(thread_t thread, ledger_t ledger, int entry, ledger_amount_t amount)
{
	ledger_amount_t old, new;
	struct ledger_entry *le;

	if (!ENTRY_VALID(ledger, entry) || (amount < 0)) {
		return KERN_INVALID_VALUE;
	}

	if (amount == 0) {
		return KERN_SUCCESS;
	}

	le = &ledger->l_entries[entry];

	old = OSAddAtomic64(amount, &le->le_credit);
	new = old + amount;
	lprintf(("%p Credit %lld->%lld\n", thread, old, new));

	if (thread) {
		ledger_entry_check_new_balance(thread, ledger, entry, le);
	}

	return KERN_SUCCESS;
}

/*
 * Add value to an entry in a ledger.
 */
kern_return_t
ledger_credit(ledger_t ledger, int entry, ledger_amount_t amount)
{
	return ledger_credit_thread(current_thread(), ledger, entry, amount);
}

/*
 * Add value to an entry in a ledger; do not check balance after update.
 */
kern_return_t
ledger_credit_nocheck(ledger_t ledger, int entry, ledger_amount_t amount)
{
	return ledger_credit_thread(NULL, ledger, entry, amount);
}

/* Add all of one ledger's values into another.
 * They must have been created from the same template.
 * This is not done atomically. Another thread (if not otherwise synchronized)
 * may see bogus values when comparing one entry to another.
 * As each entry's credit & debit are modified one at a time, the warning/limit
 * may spuriously trip, or spuriously fail to trip, or another thread (if not
 * otherwise synchronized) may see a bogus balance.
 */
kern_return_t
ledger_rollup(ledger_t to_ledger, ledger_t from_ledger)
{
	int i;

	assert(to_ledger->l_template->lt_cnt == from_ledger->l_template->lt_cnt);

	for (i = 0; i < to_ledger->l_size; i++) {
		ledger_rollup_entry(to_ledger, from_ledger, i);
	}

	return KERN_SUCCESS;
}

/* Add one ledger entry value to another.
 * They must have been created from the same template.
 * Since the credit and debit values are added one
 * at a time, other thread might read the a bogus value.
 */
kern_return_t
ledger_rollup_entry(ledger_t to_ledger, ledger_t from_ledger, int entry)
{
	struct ledger_entry *from_le, *to_le;

	assert(to_ledger->l_template->lt_cnt == from_ledger->l_template->lt_cnt);
	if (ENTRY_VALID(from_ledger, entry) && ENTRY_VALID(to_ledger, entry)) {
		from_le = &from_ledger->l_entries[entry];
		to_le   =   &to_ledger->l_entries[entry];
		OSAddAtomic64(from_le->le_credit, &to_le->le_credit);
		OSAddAtomic64(from_le->le_debit, &to_le->le_debit);
	}

	return KERN_SUCCESS;
}

/*
 * Zero the balance of a ledger by adding to its credit or debit, whichever is smaller.
 * Note that some clients of ledgers (notably, task wakeup statistics) require that
 * le_credit only ever increase as a function of ledger_credit().
 */
kern_return_t
ledger_zero_balance(ledger_t ledger, int entry)
{
	struct ledger_entry *le;
	ledger_amount_t debit, credit;

	if (!ENTRY_VALID(ledger, entry)) {
		return KERN_INVALID_VALUE;
	}

	le = &ledger->l_entries[entry];

top:
	debit = le->le_debit;
	credit = le->le_credit;

	if (le->le_flags & LF_TRACK_CREDIT_ONLY) {
		assert(le->le_debit == 0);
		if (!OSCompareAndSwap64(credit, 0, &le->le_credit)) {
			goto top;
		}
		lprintf(("%p zeroed %lld->%lld\n", current_thread(), le->le_credit, 0));
	} else if (credit > debit) {
		if (!OSCompareAndSwap64(debit, credit, &le->le_debit)) {
			goto top;
		}
		lprintf(("%p zeroed %lld->%lld\n", current_thread(), le->le_debit, le->le_credit));
	} else if (credit < debit) {
		if (!OSCompareAndSwap64(credit, debit, &le->le_credit)) {
			goto top;
		}
		lprintf(("%p zeroed %lld->%lld\n", current_thread(), le->le_credit, le->le_debit));
	}

	return KERN_SUCCESS;
}

kern_return_t
ledger_get_limit(ledger_t ledger, int entry, ledger_amount_t *limit)
{
	struct ledger_entry *le;

	if (!ENTRY_VALID(ledger, entry)) {
		return KERN_INVALID_VALUE;
	}

	le = &ledger->l_entries[entry];
	*limit = le->le_limit;

	lprintf(("ledger_get_limit: %lld\n", *limit));

	return KERN_SUCCESS;
}

/*
 * Adjust the limit of a limited resource.  This does not affect the
 * current balance, so the change doesn't affect the thread until the
 * next refill.
 *
 * warn_level: If non-zero, causes the callback to be invoked when
 * the balance exceeds this level. Specified as a percentage [of the limit].
 */
kern_return_t
ledger_set_limit(ledger_t ledger, int entry, ledger_amount_t limit,
    uint8_t warn_level_percentage)
{
	struct ledger_entry *le;

	if (!ENTRY_VALID(ledger, entry)) {
		return KERN_INVALID_VALUE;
	}

	lprintf(("ledger_set_limit: %lld\n", limit));
	le = &ledger->l_entries[entry];

	if (limit == LEDGER_LIMIT_INFINITY) {
		/*
		 * Caller wishes to disable the limit. This will implicitly
		 * disable automatic refill, as refills implicitly depend
		 * on the limit.
		 */
		ledger_disable_refill(ledger, entry);
	}

	le->le_limit = limit;
	if (le->le_flags & LF_REFILL_SCHEDULED) {
		assert(!(le->le_flags & LF_TRACKING_MAX));
		le->_le.le_refill.le_last_refill = 0;
	}
	flag_clear(&le->le_flags, LF_CALLED_BACK);
	flag_clear(&le->le_flags, LF_WARNED);
	ledger_limit_entry_wakeup(le);

	if (warn_level_percentage != 0) {
		assert(warn_level_percentage <= 100);
		assert(limit > 0); /* no negative limit support for warnings */
		assert(limit != LEDGER_LIMIT_INFINITY); /* warn % without limit makes no sense */
		le->le_warn_percent = warn_level_percentage * (1u << 16) / 100;
	} else {
		le->le_warn_percent = LEDGER_PERCENT_NONE;
	}

	return KERN_SUCCESS;
}

#if CONFIG_LEDGER_INTERVAL_MAX
kern_return_t
ledger_get_interval_max(ledger_t ledger, int entry,
    ledger_amount_t *max_interval_balance, int reset)
{
	struct ledger_entry *le;
	le = &ledger->l_entries[entry];

	if (!ENTRY_VALID(ledger, entry) || !(le->le_flags & LF_TRACKING_MAX)) {
		return KERN_INVALID_VALUE;
	}

	*max_interval_balance = le->_le._le_max.le_interval_max;
	lprintf(("ledger_get_interval_max: %lld%s\n", *max_interval_balance,
	    (reset) ? " --> 0" : ""));

	if (reset) {
		le->_le._le_max.le_interval_max = 0;
	}

	return KERN_SUCCESS;
}
#endif /* CONFIG_LEDGER_INTERVAL_MAX */

kern_return_t
ledger_get_lifetime_max(ledger_t ledger, int entry,
    ledger_amount_t *max_lifetime_balance)
{
	struct ledger_entry *le;
	le = &ledger->l_entries[entry];

	if (!ENTRY_VALID(ledger, entry) || !(le->le_flags & LF_TRACKING_MAX)) {
		return KERN_INVALID_VALUE;
	}

	*max_lifetime_balance = le->_le._le_max.le_lifetime_max;
	lprintf(("ledger_get_lifetime_max: %lld\n", *max_lifetime_balance));

	return KERN_SUCCESS;
}

/*
 * Enable tracking of periodic maximums for this ledger entry.
 */
kern_return_t
ledger_track_maximum(ledger_template_t template, int entry,
    __unused int period_in_secs)
{
	template_lock(template);

	if ((entry < 0) || (entry >= template->lt_cnt)) {
		template_unlock(template);
		return KERN_INVALID_VALUE;
	}

	/* Refill is incompatible with max tracking. */
	if (template->lt_entries[entry].et_flags & LF_REFILL_SCHEDULED) {
		return KERN_INVALID_VALUE;
	}

	template->lt_entries[entry].et_flags |= LF_TRACKING_MAX;
	template_unlock(template);

	return KERN_SUCCESS;
}

kern_return_t
ledger_panic_on_negative(ledger_template_t template, int entry)
{
	template_lock(template);

	if ((entry < 0) || (entry >= template->lt_cnt)) {
		template_unlock(template);
		return KERN_INVALID_VALUE;
	}

	template->lt_entries[entry].et_flags |= LF_PANIC_ON_NEGATIVE;

	template_unlock(template);

	return KERN_SUCCESS;
}

kern_return_t
ledger_track_credit_only(ledger_template_t template, int entry)
{
	template_lock(template);

	if ((entry < 0) || (entry >= template->lt_cnt)) {
		template_unlock(template);
		return KERN_INVALID_VALUE;
	}

	template->lt_entries[entry].et_flags |= LF_TRACK_CREDIT_ONLY;

	template_unlock(template);

	return KERN_SUCCESS;
}

/*
 * Add a callback to be executed when the resource goes into deficit.
 */
kern_return_t
ledger_set_callback(ledger_template_t template, int entry,
    ledger_callback_t func, const void *param0, const void *param1)
{
	struct entry_template *et;
	struct ledger_callback *old_cb, *new_cb;

	if ((entry < 0) || (entry >= template->lt_cnt)) {
		return KERN_INVALID_VALUE;
	}

	if (func) {
		new_cb = (struct ledger_callback *)kalloc(sizeof(*new_cb));
		new_cb->lc_func = func;
		new_cb->lc_param0 = param0;
		new_cb->lc_param1 = param1;
	} else {
		new_cb = NULL;
	}

	template_lock(template);
	et = &template->lt_entries[entry];
	old_cb = et->et_callback;
	et->et_callback = new_cb;
	template_unlock(template);
	if (old_cb) {
		kfree(old_cb, sizeof(*old_cb));
	}

	return KERN_SUCCESS;
}

/*
 * Disable callback notification for a specific ledger entry.
 *
 * Otherwise, if using a ledger template which specified a
 * callback function (ledger_set_callback()), it will be invoked when
 * the resource goes into deficit.
 */
kern_return_t
ledger_disable_callback(ledger_t ledger, int entry)
{
	if (!ENTRY_VALID(ledger, entry)) {
		return KERN_INVALID_VALUE;
	}

	/*
	 * le_warn_percent is used to indicate *if* this ledger has a warning configured,
	 * in addition to what that warning level is set to.
	 * This means a side-effect of ledger_disable_callback() is that the
	 * warning level is forgotten.
	 */
	ledger->l_entries[entry].le_warn_percent = LEDGER_PERCENT_NONE;
	flag_clear(&ledger->l_entries[entry].le_flags, LEDGER_ACTION_CALLBACK);
	return KERN_SUCCESS;
}

/*
 * Enable callback notification for a specific ledger entry.
 *
 * This is only needed if ledger_disable_callback() has previously
 * been invoked against an entry; there must already be a callback
 * configured.
 */
kern_return_t
ledger_enable_callback(ledger_t ledger, int entry)
{
	if (!ENTRY_VALID(ledger, entry)) {
		return KERN_INVALID_VALUE;
	}

	assert(entry_get_callback(ledger, entry) != NULL);

	flag_set(&ledger->l_entries[entry].le_flags, LEDGER_ACTION_CALLBACK);
	return KERN_SUCCESS;
}

/*
 * Query the automatic refill period for this ledger entry.
 *
 * A period of 0 means this entry has none configured.
 */
kern_return_t
ledger_get_period(ledger_t ledger, int entry, uint64_t *period)
{
	struct ledger_entry *le;

	if (!ENTRY_VALID(ledger, entry)) {
		return KERN_INVALID_VALUE;
	}

	le = &ledger->l_entries[entry];
	*period = abstime_to_nsecs(le->_le.le_refill.le_refill_period);
	lprintf(("ledger_get_period: %llx\n", *period));
	return KERN_SUCCESS;
}

/*
 * Adjust the automatic refill period.
 */
kern_return_t
ledger_set_period(ledger_t ledger, int entry, uint64_t period)
{
	struct ledger_entry *le;

	lprintf(("ledger_set_period: %llx\n", period));
	if (!ENTRY_VALID(ledger, entry)) {
		return KERN_INVALID_VALUE;
	}

	le = &ledger->l_entries[entry];

	/*
	 * A refill period refills the ledger in multiples of the limit,
	 * so if you haven't set one yet, you need a lesson on ledgers.
	 */
	assert(le->le_limit != LEDGER_LIMIT_INFINITY);

	if (le->le_flags & LF_TRACKING_MAX) {
		/*
		 * Refill is incompatible with rolling max tracking.
		 */
		return KERN_INVALID_VALUE;
	}

	le->_le.le_refill.le_refill_period = nsecs_to_abstime(period);

	/*
	 * Set the 'starting time' for the next refill to now. Since
	 * we're resetting the balance to zero here, we consider this
	 * moment the starting time for accumulating a balance that
	 * counts towards the limit.
	 */
	le->_le.le_refill.le_last_refill = mach_absolute_time();
	ledger_zero_balance(ledger, entry);

	flag_set(&le->le_flags, LF_REFILL_SCHEDULED);

	return KERN_SUCCESS;
}

/*
 * Disable automatic refill.
 */
kern_return_t
ledger_disable_refill(ledger_t ledger, int entry)
{
	struct ledger_entry *le;

	if (!ENTRY_VALID(ledger, entry)) {
		return KERN_INVALID_VALUE;
	}

	le = &ledger->l_entries[entry];

	flag_clear(&le->le_flags, LF_REFILL_SCHEDULED);

	return KERN_SUCCESS;
}

kern_return_t
ledger_get_actions(ledger_t ledger, int entry, int *actions)
{
	if (!ENTRY_VALID(ledger, entry)) {
		return KERN_INVALID_VALUE;
	}

	*actions = ledger->l_entries[entry].le_flags & LEDGER_ACTION_MASK;
	lprintf(("ledger_get_actions: %#x\n", *actions));
	return KERN_SUCCESS;
}

kern_return_t
ledger_set_action(ledger_t ledger, int entry, int action)
{
	lprintf(("ledger_set_action: %#x\n", action));
	if (!ENTRY_VALID(ledger, entry)) {
		return KERN_INVALID_VALUE;
	}

	flag_set(&ledger->l_entries[entry].le_flags, action);
	return KERN_SUCCESS;
}

kern_return_t
ledger_debit_thread(thread_t thread, ledger_t ledger, int entry, ledger_amount_t amount)
{
	struct ledger_entry *le;
	ledger_amount_t old, new;

	if (!ENTRY_VALID(ledger, entry) || (amount < 0)) {
		return KERN_INVALID_ARGUMENT;
	}

	if (amount == 0) {
		return KERN_SUCCESS;
	}

	le = &ledger->l_entries[entry];

	if (le->le_flags & LF_TRACK_CREDIT_ONLY) {
		assert(le->le_debit == 0);
		old = OSAddAtomic64(-amount, &le->le_credit);
		new = old - amount;
	} else {
		old = OSAddAtomic64(amount, &le->le_debit);
		new = old + amount;
	}
	lprintf(("%p Debit %lld->%lld\n", thread, old, new));

	if (thread) {
		ledger_entry_check_new_balance(thread, ledger, entry, le);
	}

	return KERN_SUCCESS;
}

kern_return_t
ledger_debit(ledger_t ledger, int entry, ledger_amount_t amount)
{
	return ledger_debit_thread(current_thread(), ledger, entry, amount);
}

kern_return_t
ledger_debit_nocheck(ledger_t ledger, int entry, ledger_amount_t amount)
{
	return ledger_debit_thread(NULL, ledger, entry, amount);
}

void
ledger_ast(thread_t thread)
{
	struct ledger   *l = thread->t_ledger;
	struct ledger   *thl;
	struct ledger   *coalition_ledger;
	uint32_t        block;
	uint64_t        now;
	uint8_t         task_flags;
	uint8_t         task_percentage;
	uint64_t        task_interval;

	kern_return_t ret;
	task_t task = thread->task;

	lprintf(("Ledger AST for %p\n", thread));

	ASSERT(task != NULL);
	ASSERT(thread == current_thread());

top:
	/*
	 * Take a self-consistent snapshot of the CPU usage monitor parameters. The task
	 * can change them at any point (with the task locked).
	 */
	task_lock(task);
	task_flags = task->rusage_cpu_flags;
	task_percentage = task->rusage_cpu_perthr_percentage;
	task_interval = task->rusage_cpu_perthr_interval;
	task_unlock(task);

	/*
	 * Make sure this thread is up to date with regards to any task-wide per-thread
	 * CPU limit, but only if it doesn't have a thread-private blocking CPU limit.
	 */
	if (((task_flags & TASK_RUSECPU_FLAGS_PERTHR_LIMIT) != 0) &&
	    ((thread->options & TH_OPT_PRVT_CPULIMIT) == 0)) {
		uint8_t  percentage;
		uint64_t interval;
		int      action;

		thread_get_cpulimit(&action, &percentage, &interval);

		/*
		 * If the thread's CPU limits no longer match the task's, or the
		 * task has a limit but the thread doesn't, update the limit.
		 */
		if (((thread->options & TH_OPT_PROC_CPULIMIT) == 0) ||
		    (interval != task_interval) || (percentage != task_percentage)) {
			thread_set_cpulimit(THREAD_CPULIMIT_EXCEPTION, task_percentage, task_interval);
			assert((thread->options & TH_OPT_PROC_CPULIMIT) != 0);
		}
	} else if (((task_flags & TASK_RUSECPU_FLAGS_PERTHR_LIMIT) == 0) &&
	    (thread->options & TH_OPT_PROC_CPULIMIT)) {
		assert((thread->options & TH_OPT_PRVT_CPULIMIT) == 0);

		/*
		 * Task no longer has a per-thread CPU limit; remove this thread's
		 * corresponding CPU limit.
		 */
		thread_set_cpulimit(THREAD_CPULIMIT_DISABLE, 0, 0);
		assert((thread->options & TH_OPT_PROC_CPULIMIT) == 0);
	}

	/*
	 * If the task or thread is being terminated, let's just get on with it
	 */
	if ((l == NULL) || !task->active || task->halting || !thread->active) {
		return;
	}

	/*
	 * Examine all entries in deficit to see which might be eligble for
	 * an automatic refill, which require callbacks to be issued, and
	 * which require blocking.
	 */
	block = 0;
	now = mach_absolute_time();

	/*
	 * Note that thread->t_threadledger may have been changed by the
	 * thread_set_cpulimit() call above - so don't examine it until afterwards.
	 */
	thl = thread->t_threadledger;
	if (LEDGER_VALID(thl)) {
		block |= ledger_check_needblock(thl, now);
	}
	block |= ledger_check_needblock(l, now);

	coalition_ledger = coalition_ledger_get_from_task(task);
	if (LEDGER_VALID(coalition_ledger)) {
		block |= ledger_check_needblock(coalition_ledger, now);
	}
	ledger_dereference(coalition_ledger);
	/*
	 * If we are supposed to block on the availability of one or more
	 * resources, find the first entry in deficit for which we should wait.
	 * Schedule a refill if necessary and then sleep until the resource
	 * becomes available.
	 */
	if (block) {
		if (LEDGER_VALID(thl)) {
			ret = ledger_perform_blocking(thl);
			if (ret != KERN_SUCCESS) {
				goto top;
			}
		}
		ret = ledger_perform_blocking(l);
		if (ret != KERN_SUCCESS) {
			goto top;
		}
	} /* block */
}

static uint32_t
ledger_check_needblock(ledger_t l, uint64_t now)
{
	int i;
	uint32_t flags, block = 0;
	struct ledger_entry *le;
	struct ledger_callback *lc;


	for (i = 0; i < l->l_size; i++) {
		le = &l->l_entries[i];

		lc = entry_get_callback(l, i);

		if (limit_exceeded(le) == FALSE) {
			if (le->le_flags & LEDGER_ACTION_CALLBACK) {
				/*
				 * If needed, invoke the callback as a warning.
				 * This needs to happen both when the balance rises above
				 * the warning level, and also when it dips back below it.
				 */
				assert(lc != NULL);
				/*
				 * See comments for matching logic in ledger_check_new_balance().
				 */
				if (warn_level_exceeded(le)) {
					flags = flag_set(&le->le_flags, LF_WARNED);
					if ((flags & LF_WARNED) == 0) {
						lc->lc_func(LEDGER_WARNING_ROSE_ABOVE, lc->lc_param0, lc->lc_param1);
					}
				} else {
					flags = flag_clear(&le->le_flags, LF_WARNED);
					if (flags & LF_WARNED) {
						lc->lc_func(LEDGER_WARNING_DIPPED_BELOW, lc->lc_param0, lc->lc_param1);
					}
				}
			}

			continue;
		}

		/* We're over the limit, so refill if we are eligible and past due. */
		if (le->le_flags & LF_REFILL_SCHEDULED) {
			assert(!(le->le_flags & LF_TRACKING_MAX));

			if ((le->_le.le_refill.le_last_refill + le->_le.le_refill.le_refill_period) <= now) {
				ledger_refill(now, l, i);
				if (limit_exceeded(le) == FALSE) {
					continue;
				}
			}
		}

		if (le->le_flags & LEDGER_ACTION_BLOCK) {
			block = 1;
		}
		if ((le->le_flags & LEDGER_ACTION_CALLBACK) == 0) {
			continue;
		}

		/*
		 * If the LEDGER_ACTION_CALLBACK flag is on, we expect there to
		 * be a registered callback.
		 */
		assert(lc != NULL);
		flags = flag_set(&le->le_flags, LF_CALLED_BACK);
		/* Callback has already been called */
		if (flags & LF_CALLED_BACK) {
			continue;
		}
		lc->lc_func(FALSE, lc->lc_param0, lc->lc_param1);
	}
	return block;
}


/* return KERN_SUCCESS to continue, KERN_FAILURE to restart */
static kern_return_t
ledger_perform_blocking(ledger_t l)
{
	int i;
	kern_return_t ret;
	struct ledger_entry *le;

	for (i = 0; i < l->l_size; i++) {
		le = &l->l_entries[i];
		if ((!limit_exceeded(le)) ||
		    ((le->le_flags & LEDGER_ACTION_BLOCK) == 0)) {
			continue;
		}

		assert(!(le->le_flags & LF_TRACKING_MAX));

		/* Prepare to sleep until the resource is refilled */
		ret = assert_wait_deadline(le, THREAD_INTERRUPTIBLE,
		    le->_le.le_refill.le_last_refill + le->_le.le_refill.le_refill_period);
		if (ret != THREAD_WAITING) {
			return KERN_SUCCESS;
		}

		/* Mark that somebody is waiting on this entry  */
		flag_set(&le->le_flags, LF_WAKE_NEEDED);

		ret = thread_block_reason(THREAD_CONTINUE_NULL, NULL,
		    AST_LEDGER);
		if (ret != THREAD_AWAKENED) {
			return KERN_SUCCESS;
		}

		/*
		 * The world may have changed while we were asleep.
		 * Some other resource we need may have gone into
		 * deficit.  Or maybe we're supposed to die now.
		 * Go back to the top and reevaluate.
		 */
		return KERN_FAILURE;
	}
	return KERN_SUCCESS;
}


kern_return_t
ledger_get_entries(ledger_t ledger, int entry, ledger_amount_t *credit,
    ledger_amount_t *debit)
{
	struct ledger_entry *le;

	if (!ENTRY_VALID(ledger, entry)) {
		return KERN_INVALID_ARGUMENT;
	}

	le = &ledger->l_entries[entry];

	*credit = le->le_credit;
	*debit = le->le_debit;

	return KERN_SUCCESS;
}

kern_return_t
ledger_reset_callback_state(ledger_t ledger, int entry)
{
	struct ledger_entry *le;

	if (!ENTRY_VALID(ledger, entry)) {
		return KERN_INVALID_ARGUMENT;
	}

	le = &ledger->l_entries[entry];

	flag_clear(&le->le_flags, LF_CALLED_BACK);

	return KERN_SUCCESS;
}

kern_return_t
ledger_disable_panic_on_negative(ledger_t ledger, int entry)
{
	struct ledger_entry *le;

	if (!ENTRY_VALID(ledger, entry)) {
		return KERN_INVALID_ARGUMENT;
	}

	le = &ledger->l_entries[entry];

	flag_clear(&le->le_flags, LF_PANIC_ON_NEGATIVE);

	return KERN_SUCCESS;
}

kern_return_t
ledger_get_panic_on_negative(ledger_t ledger, int entry, int *panic_on_negative)
{
	struct ledger_entry *le;

	if (!ENTRY_VALID(ledger, entry)) {
		return KERN_INVALID_ARGUMENT;
	}

	le = &ledger->l_entries[entry];

	if (le->le_flags & LF_PANIC_ON_NEGATIVE) {
		*panic_on_negative = TRUE;
	} else {
		*panic_on_negative = FALSE;
	}

	return KERN_SUCCESS;
}

kern_return_t
ledger_get_balance(ledger_t ledger, int entry, ledger_amount_t *balance)
{
	struct ledger_entry *le;

	if (!ENTRY_VALID(ledger, entry)) {
		return KERN_INVALID_ARGUMENT;
	}

	le = &ledger->l_entries[entry];

	if (le->le_flags & LF_TRACK_CREDIT_ONLY) {
		assert(le->le_debit == 0);
	} else {
		assert((le->le_credit >= 0) && (le->le_debit >= 0));
	}

	*balance = le->le_credit - le->le_debit;

	return KERN_SUCCESS;
}

int
ledger_template_info(void **buf, int *len)
{
	struct ledger_template_info *lti;
	struct entry_template *et;
	int i;
	ledger_t l;

	/*
	 * Since all tasks share a ledger template, we'll just use the
	 * caller's as the source.
	 */
	l = current_task()->ledger;
	if ((*len < 0) || (l == NULL)) {
		return EINVAL;
	}

	if (*len > l->l_size) {
		*len = l->l_size;
	}
	lti = kalloc((*len) * sizeof(struct ledger_template_info));
	if (lti == NULL) {
		return ENOMEM;
	}
	*buf = lti;

	template_lock(l->l_template);
	et = l->l_template->lt_entries;

	for (i = 0; i < *len; i++) {
		memset(lti, 0, sizeof(*lti));
		strlcpy(lti->lti_name, et->et_key, LEDGER_NAME_MAX);
		strlcpy(lti->lti_group, et->et_group, LEDGER_NAME_MAX);
		strlcpy(lti->lti_units, et->et_units, LEDGER_NAME_MAX);
		et++;
		lti++;
	}
	template_unlock(l->l_template);

	return 0;
}

static void
ledger_fill_entry_info(struct ledger_entry      *le,
    struct ledger_entry_info *lei,
    uint64_t                  now)
{
	assert(le != NULL);
	assert(lei != NULL);

	memset(lei, 0, sizeof(*lei));

	lei->lei_limit         = le->le_limit;
	lei->lei_credit        = le->le_credit;
	lei->lei_debit         = le->le_debit;
	lei->lei_balance       = lei->lei_credit - lei->lei_debit;
	lei->lei_refill_period = (le->le_flags & LF_REFILL_SCHEDULED) ?
	    abstime_to_nsecs(le->_le.le_refill.le_refill_period) : 0;
	lei->lei_last_refill   = abstime_to_nsecs(now - le->_le.le_refill.le_last_refill);
}

int
ledger_get_task_entry_info_multiple(task_t task, void **buf, int *len)
{
	struct ledger_entry_info *lei;
	struct ledger_entry *le;
	uint64_t now = mach_absolute_time();
	int i;
	ledger_t l;

	if ((*len < 0) || ((l = task->ledger) == NULL)) {
		return EINVAL;
	}

	if (*len > l->l_size) {
		*len = l->l_size;
	}
	lei = kalloc((*len) * sizeof(struct ledger_entry_info));
	if (lei == NULL) {
		return ENOMEM;
	}
	*buf = lei;

	le = l->l_entries;

	for (i = 0; i < *len; i++) {
		ledger_fill_entry_info(le, lei, now);
		le++;
		lei++;
	}

	return 0;
}

void
ledger_get_entry_info(ledger_t                  ledger,
    int                       entry,
    struct ledger_entry_info *lei)
{
	uint64_t now = mach_absolute_time();

	assert(ledger != NULL);
	assert(lei != NULL);

	if (entry >= 0 && entry < ledger->l_size) {
		struct ledger_entry *le = &ledger->l_entries[entry];
		ledger_fill_entry_info(le, lei, now);
	}
}

int
ledger_info(task_t task, struct ledger_info *info)
{
	ledger_t l;

	if ((l = task->ledger) == NULL) {
		return ENOENT;
	}

	memset(info, 0, sizeof(*info));

	strlcpy(info->li_name, l->l_template->lt_name, LEDGER_NAME_MAX);
	info->li_id = l->l_id;
	info->li_entries = l->l_size;
	return 0;
}

#ifdef LEDGER_DEBUG
int
ledger_limit(task_t task, struct ledger_limit_args *args)
{
	ledger_t l;
	int64_t limit;
	int idx;

	if ((l = task->ledger) == NULL) {
		return EINVAL;
	}

	idx = ledger_key_lookup(l->l_template, args->lla_name);
	if ((idx < 0) || (idx >= l->l_size)) {
		return EINVAL;
	}

	/*
	 * XXX - this doesn't really seem like the right place to have
	 * a context-sensitive conversion of userspace units into kernel
	 * units.  For now I'll handwave and say that the ledger() system
	 * call isn't meant for civilians to use - they should be using
	 * the process policy interfaces.
	 */
	if (idx == task_ledgers.cpu_time) {
		int64_t nsecs;

		if (args->lla_refill_period) {
			/*
			 * If a refill is scheduled, then the limit is
			 * specified as a percentage of one CPU.  The
			 * syscall specifies the refill period in terms of
			 * milliseconds, so we need to convert to nsecs.
			 */
			args->lla_refill_period *= 1000000;
			nsecs = args->lla_limit *
			    (args->lla_refill_period / 100);
			lprintf(("CPU limited to %lld nsecs per second\n",
			    nsecs));
		} else {
			/*
			 * If no refill is scheduled, then this is a
			 * fixed amount of CPU time (in nsecs) that can
			 * be consumed.
			 */
			nsecs = args->lla_limit;
			lprintf(("CPU limited to %lld nsecs\n", nsecs));
		}
		limit = nsecs_to_abstime(nsecs);
	} else {
		limit = args->lla_limit;
		lprintf(("%s limited to %lld\n", args->lla_name, limit));
	}

	if (args->lla_refill_period > 0) {
		ledger_set_period(l, idx, args->lla_refill_period);
	}

	ledger_set_limit(l, idx, limit);
	flag_set(&l->l_entries[idx].le_flags, LEDGER_ACTION_BLOCK);
	return 0;
}
#endif
