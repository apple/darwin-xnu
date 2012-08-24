/*
 * Copyright (c) 2010 Apple Computer, Inc. All rights reserved.
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

#include <kern/lock.h>
#include <kern/ledger.h>
#include <kern/kalloc.h>
#include <kern/task.h>

#include <kern/processor.h>
#include <kern/machine.h>
#include <kern/queue.h>
#include <sys/errno.h>

#include <libkern/OSAtomic.h>
#include <mach/mach_types.h>

/*
 * Ledger entry flags. Bits in second nibble (masked by 0xF0) are used for
 * ledger actions (LEDGER_ACTION_BLOCK, etc).
 */
#define	ENTRY_ACTIVE		0x0001	/* entry is active if set */
#define	WAKE_NEEDED		0x0100	/* one or more threads are asleep */
#define	WAKE_INPROGRESS		0x0200	/* the wait queue is being processed */
#define	REFILL_SCHEDULED	0x0400	/* a refill timer has been set */
#define	REFILL_INPROGRESS	0x0800	/* the ledger is being refilled */
#define	CALLED_BACK		0x1000	/* callback has already been called */

/* Determine whether a ledger entry exists and has been initialized and active */
#define	ENTRY_VALID(l, e)					\
	(((l) != NULL) && ((e) >= 0) && ((e) < (l)->l_size) &&	\
	(((l)->l_entries[e].le_flags & ENTRY_ACTIVE) == ENTRY_ACTIVE))

#ifdef LEDGER_DEBUG
int ledger_debug = 0;

#define ASSERT(a) assert(a)
#define	lprintf(a) if (ledger_debug) {					\
	printf("%lld  ", abstime_to_nsecs(mach_absolute_time() / 1000000)); \
	printf a ;							\
}
#else
#define	lprintf(a)
#define	ASSERT(a)
#endif

struct ledger_callback {
	ledger_callback_t	lc_func;
	const void		*lc_param0;
	const void		*lc_param1;
};

struct entry_template {
	char			et_key[LEDGER_NAME_MAX];
	char			et_group[LEDGER_NAME_MAX];
	char			et_units[LEDGER_NAME_MAX];
	uint32_t		et_flags;
	struct ledger_callback	*et_callback;
};

lck_grp_t ledger_lck_grp;

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
	const char		*lt_name;
	int			lt_refs;
	int			lt_cnt;
	int			lt_table_size;
	volatile uint32_t	lt_inuse;
	lck_mtx_t		lt_lock;
	struct entry_template	*lt_entries;
};

#define template_lock(template)		lck_mtx_lock(&(template)->lt_lock)
#define template_unlock(template)	lck_mtx_unlock(&(template)->lt_lock)

#define TEMPLATE_INUSE(s, t) { 					\
	s = splsched();						\
	while (OSCompareAndSwap(0, 1, &((t)->lt_inuse)))	\
		;						\
}

#define TEMPLATE_IDLE(s, t) { 					\
	(t)->lt_inuse = 0;					\
	splx(s);						\
}

/*
 * The explicit alignment is to ensure that atomic operations don't panic
 * on ARM.
 */
struct ledger_entry {
	volatile uint32_t		le_flags;
        ledger_amount_t			le_limit;
        volatile ledger_amount_t	le_credit __attribute__((aligned(8)));
        volatile ledger_amount_t	le_debit __attribute__((aligned(8)));
	/*
	 * XXX - the following two fields can go away if we move all of
	 * the refill logic into process policy
	 */
	uint64_t			le_refill_period;
	uint64_t			le_last_refill;
} __attribute__((aligned(8)));

struct ledger {
	int			l_id;
	struct ledger_template	*l_template;
	int			l_refs;
	int			l_size;
	struct ledger_entry	*l_entries;
};

static int ledger_cnt = 0;
/* ledger ast helper functions */
static uint32_t ledger_check_needblock(ledger_t l, uint64_t now);
static kern_return_t ledger_perform_blocking(ledger_t l);
static uint32_t flag_set(volatile uint32_t *flags, uint32_t bit);
static uint32_t flag_clear(volatile uint32_t *flags, uint32_t bit);

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
	return (nsecs);
}

static uint64_t
nsecs_to_abstime(uint64_t nsecs)
{
	uint64_t abstime;

	nanoseconds_to_absolutetime(nsecs, &abstime);
	return (abstime);
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

	template = (ledger_template_t)kalloc(sizeof (*template));
	if (template == NULL)
		return (NULL);

	template->lt_name = name;
	template->lt_refs = 1;
	template->lt_cnt = 0;
	template->lt_table_size = 1;
	template->lt_inuse = 0;
	lck_mtx_init(&template->lt_lock, &ledger_lck_grp, LCK_ATTR_NULL);

	template->lt_entries = (struct entry_template *)
	    kalloc(sizeof (struct entry_template) * template->lt_table_size);
	if (template->lt_entries == NULL) {
		kfree(template, sizeof (*template));
		template = NULL;
	}

	return (template);
}

void
ledger_template_dereference(ledger_template_t template)
{
	template_lock(template);
	template->lt_refs--;
	template_unlock(template);

	if (template->lt_refs == 0)
		kfree(template, sizeof (*template));
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

	if ((key == NULL) || (strlen(key) >= LEDGER_NAME_MAX))
		return (-1);

	template_lock(template);

	/* If the table is full, attempt to double its size */
	if (template->lt_cnt == template->lt_table_size) {
		struct entry_template *new_entries, *old_entries;
		int old_cnt, old_sz;
		spl_t s;

		old_cnt = template->lt_table_size;
		old_sz = (int)(old_cnt * sizeof (struct entry_template));
		new_entries = kalloc(old_sz * 2);
		if (new_entries == NULL) {
			template_unlock(template);
			return (-1);
		}
		memcpy(new_entries, template->lt_entries, old_sz);
		memset(((char *)new_entries) + old_sz, 0, old_sz);
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
	et->et_flags = ENTRY_ACTIVE;
	et->et_callback = NULL;

	idx = template->lt_cnt++;
	template_unlock(template);

	return (idx);
}


kern_return_t
ledger_entry_setactive(ledger_t ledger, int entry)
{
	struct ledger_entry *le;

	if ((ledger == NULL)  || (entry < 0) || (entry >= ledger->l_size))
		return (KERN_INVALID_ARGUMENT);

	le = &ledger->l_entries[entry];
	if ((le->le_flags & ENTRY_ACTIVE) == 0) {
		flag_set(&le->le_flags, ENTRY_ACTIVE);
	}
	return (KERN_SUCCESS);
}


int
ledger_key_lookup(ledger_template_t template, const char *key)
{
	int idx;

	template_lock(template);
	for (idx = 0; idx < template->lt_cnt; idx++)
		if (template->lt_entries[idx].et_key &&
		    (strcmp(key, template->lt_entries[idx].et_key) == 0))
			break;

	if (idx >= template->lt_cnt)
		idx = -1;
	template_unlock(template);

	return (idx);
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
	size_t sz;
	int i;

	ledger = (ledger_t)kalloc(sizeof (struct ledger));
	if (ledger == NULL)
		return (LEDGER_NULL);

	ledger->l_template = template;
	ledger->l_id = ledger_cnt++;
	ledger->l_refs = 1;

	template_lock(template);
	template->lt_refs++;
	ledger->l_size = template->lt_cnt;
	template_unlock(template);

	sz = ledger->l_size * sizeof (struct ledger_entry);
	ledger->l_entries = kalloc(sz);
	if (sz && (ledger->l_entries == NULL)) {
		ledger_template_dereference(template);
		kfree(ledger, sizeof(struct ledger));
		return (LEDGER_NULL);
	}

	template_lock(template);
	assert(ledger->l_size <= template->lt_cnt);
	for (i = 0; i < ledger->l_size; i++) {
		struct ledger_entry *le = &ledger->l_entries[i];
		struct entry_template *et = &template->lt_entries[i];

		le->le_flags = et->et_flags;
		/* make entry inactive by removing  active bit */
		if (entry_type == LEDGER_CREATE_INACTIVE_ENTRIES)
			flag_clear(&le->le_flags, ENTRY_ACTIVE);
		/*
		 * If template has a callback, this entry is opted-in,
		 * by default.
		 */
		if (et->et_callback != NULL)
			flag_set(&le->le_flags, LEDGER_ACTION_CALLBACK);
		le->le_credit = 0;
		le->le_debit = 0;
		le->le_limit = LEDGER_LIMIT_INFINITY;
		le->le_refill_period = 0;
	}
	template_unlock(template);

	return (ledger);
}

static uint32_t
flag_set(volatile uint32_t *flags, uint32_t bit)
{
	return (OSBitOrAtomic(bit, flags));
}

static uint32_t
flag_clear(volatile uint32_t *flags, uint32_t bit)
{
	return (OSBitAndAtomic(~bit, flags));
}

/*
 * Take a reference on a ledger
 */
kern_return_t
ledger_reference(ledger_t ledger)
{
	if (!LEDGER_VALID(ledger))
		return (KERN_INVALID_ARGUMENT);
	OSIncrementAtomic(&ledger->l_refs);
	return (KERN_SUCCESS);
}

int
ledger_reference_count(ledger_t ledger)
{
	if (!LEDGER_VALID(ledger))
		return (-1);

	return (ledger->l_refs);
}

/*
 * Remove a reference on a ledger.  If this is the last reference,
 * deallocate the unused ledger.
 */
kern_return_t
ledger_dereference(ledger_t ledger)
{
	int v;

	if (!LEDGER_VALID(ledger))
		return (KERN_INVALID_ARGUMENT);

	v = OSDecrementAtomic(&ledger->l_refs);
	ASSERT(v >= 1);

	/* Just released the last reference.  Free it. */
	if (v == 1) {
		kfree(ledger->l_entries,
		    ledger->l_size * sizeof (struct ledger_entry));
		kfree(ledger, sizeof (*ledger));
	}

	return (KERN_SUCCESS);
}

/*
 * Determine whether an entry has exceeded its limit.
 */
static inline int
limit_exceeded(struct ledger_entry *le)
{
	ledger_amount_t balance;

	balance = le->le_credit - le->le_debit;
	if ((le->le_limit <= 0) && (balance < le->le_limit))
		return (1);

	if ((le->le_limit > 0) && (balance > le->le_limit))
		return (1);
	return (0);
}

static inline struct ledger_callback *
entry_get_callback(ledger_t ledger, int entry)
{
	struct ledger_callback *callback;
	spl_t s;

	TEMPLATE_INUSE(s, ledger->l_template);
	callback = ledger->l_template->lt_entries[entry].et_callback;
	TEMPLATE_IDLE(s, ledger->l_template);

	return (callback);
}

/*
 * If the ledger value is positive, wake up anybody waiting on it.
 */
static inline void
ledger_limit_entry_wakeup(struct ledger_entry *le)
{
	uint32_t flags;

	if (!limit_exceeded(le)) {
		flags = flag_clear(&le->le_flags, CALLED_BACK);

		while (le->le_flags & WAKE_NEEDED) {
			flag_clear(&le->le_flags, WAKE_NEEDED);
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
	int cnt;

	le = &ledger->l_entries[entry];

	/*
	 * If another thread is handling the refill already, we're not
	 * needed.  Just sit here for a few cycles while the other thread
	 * finishes updating the balance.  If it takes too long, just return
	 * and we'll block again.
	 */
	if (flag_set(&le->le_flags, REFILL_INPROGRESS) & REFILL_INPROGRESS) {
		cnt = 0;
		while (cnt++ < 100 && (le->le_flags & REFILL_INPROGRESS))
			;
		return;
	}

	/*
	 * See how many refill periods have passed since we last
	 * did a refill.
	 */
	period = le->le_refill_period;
	elapsed = now - le->le_last_refill;
	if ((period == 0) || (elapsed < period)) {
		flag_clear(&le->le_flags, REFILL_INPROGRESS);
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
	if (elapsed > 0)
		periods = (now - le->le_last_refill) / period;

	balance = le->le_credit - le->le_debit;
	due = periods * le->le_limit;
	if (balance - due < 0)
		due = balance;
	OSAddAtomic64(due, &le->le_debit);

	/*
	 * If we've completely refilled the pool, set the refill time to now.
	 * Otherwise set it to the time at which it last should have been
	 * fully refilled.
	 */
	if (balance == due)
		le->le_last_refill = now;
	else
		le->le_last_refill += (le->le_refill_period * periods);

	flag_clear(&le->le_flags, REFILL_INPROGRESS);

	lprintf(("Refill %lld %lld->%lld\n", periods, balance, balance - due));
	if (!limit_exceeded(le))
		ledger_limit_entry_wakeup(le);
}

static void
ledger_check_new_balance(ledger_t ledger, int entry)
{
	struct ledger_entry *le;
	uint64_t now;

	le = &ledger->l_entries[entry];

	/* Check to see whether we're due a refill */
	if (le->le_refill_period) {
		now = mach_absolute_time();
		if ((now - le->le_last_refill) > le->le_refill_period)
			ledger_refill(now, ledger, entry);
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
		    (!(le->le_flags & CALLED_BACK) &&
		    entry_get_callback(ledger, entry))) {
			set_astledger(current_thread());
		}
	} else {
		/*
		 * The balance on the account is below the limit.  If
		 * there are any threads blocked on this entry, now would
		 * be a good time to wake them up.
		 */
		if (le->le_flags & WAKE_NEEDED)
			ledger_limit_entry_wakeup(le);
	}
}

/*
 * Add value to an entry in a ledger.
 */
kern_return_t
ledger_credit(ledger_t ledger, int entry, ledger_amount_t amount)
{
	ledger_amount_t old, new;
	struct ledger_entry *le;

	if (!ENTRY_VALID(ledger, entry) || (amount < 0))
		return (KERN_INVALID_VALUE);

	if (amount == 0)
		return (KERN_SUCCESS);

	le = &ledger->l_entries[entry];

	old = OSAddAtomic64(amount, &le->le_credit);
	new = old + amount;
	lprintf(("%p Credit %lld->%lld\n", current_thread(), old, new));
	ledger_check_new_balance(ledger, entry);

	return (KERN_SUCCESS);
}


/*
 * Adjust the limit of a limited resource.  This does not affect the
 * current balance, so the change doesn't affect the thread until the
 * next refill.
 */
kern_return_t
ledger_set_limit(ledger_t ledger, int entry, ledger_amount_t limit)
{
	struct ledger_entry *le;

	if (!ENTRY_VALID(ledger, entry))
		return (KERN_INVALID_VALUE);

	lprintf(("ledger_set_limit: %x\n", (uint32_t)limit));
	le = &ledger->l_entries[entry];
	le->le_limit = limit;
	le->le_last_refill = 0;
	flag_clear(&le->le_flags, CALLED_BACK);
	ledger_limit_entry_wakeup(le);

	return (KERN_SUCCESS);
}

/*
 * Add a callback to be executed when the resource goes into deficit
 */
kern_return_t
ledger_set_callback(ledger_template_t template, int entry,
   ledger_callback_t func, const void *param0, const void *param1)
{
	struct entry_template *et;
	struct ledger_callback *old_cb, *new_cb;

	if ((entry < 0) || (entry >= template->lt_cnt))
		return (KERN_INVALID_VALUE);

	if (func) {
		new_cb = (struct ledger_callback *)kalloc(sizeof (*new_cb));
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
	if (old_cb)
		kfree(old_cb, sizeof (*old_cb));

	return (KERN_SUCCESS);
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
	if (!ENTRY_VALID(ledger, entry))
		return (KERN_INVALID_VALUE);

	flag_clear(&ledger->l_entries[entry].le_flags, LEDGER_ACTION_CALLBACK);
	return (KERN_SUCCESS);
}

/*
 * Clear the called_back flag, indicating that we want to be notified
 * again when the limit is next exceeded.
 */
kern_return_t
ledger_reset_callback(ledger_t ledger, int entry)
{
	if (!ENTRY_VALID(ledger, entry))
		return (KERN_INVALID_VALUE);

	flag_clear(&ledger->l_entries[entry].le_flags, CALLED_BACK);
	return (KERN_SUCCESS);
}

/*
 * Adjust the automatic refill period.
 */
kern_return_t
ledger_set_period(ledger_t ledger, int entry, uint64_t period)
{
	struct ledger_entry *le;

	lprintf(("ledger_set_period: %llx\n", period));
	if (!ENTRY_VALID(ledger, entry))
		return (KERN_INVALID_VALUE);

	le = &ledger->l_entries[entry];
	le->le_refill_period = nsecs_to_abstime(period);

	return (KERN_SUCCESS);
}

kern_return_t
ledger_set_action(ledger_t ledger, int entry, int action)
{
	lprintf(("ledger_set_action: %d\n", action));
	if (!ENTRY_VALID(ledger, entry))
		return (KERN_INVALID_VALUE);

	flag_set(&ledger->l_entries[entry].le_flags, action);
	return (KERN_SUCCESS);
}

void
set_astledger(thread_t thread)
{
	spl_t s = splsched();

	if (thread == current_thread()) {
		thread_ast_set(thread, AST_LEDGER);
		ast_propagate(thread->ast);
	} else {
		processor_t p;

		thread_lock(thread);
		thread_ast_set(thread, AST_LEDGER);
		p = thread->last_processor;
		if ((p != PROCESSOR_NULL) && (p->state == PROCESSOR_RUNNING) &&
		   (p->active_thread == thread))
			cause_ast_check(p);
		thread_unlock(thread);
	}
	
	splx(s);
}

kern_return_t
ledger_debit(ledger_t ledger, int entry, ledger_amount_t amount)
{
	struct ledger_entry *le;
	ledger_amount_t old, new;

	if (!ENTRY_VALID(ledger, entry) || (amount < 0))
		return (KERN_INVALID_ARGUMENT);

	if (amount == 0)
		return (KERN_SUCCESS);

	le = &ledger->l_entries[entry];

	old = OSAddAtomic64(amount, &le->le_debit);
	new = old + amount;

	lprintf(("%p Debit %lld->%lld\n", thread, old, new));
	ledger_check_new_balance(ledger, entry);
	return (KERN_SUCCESS);

}

void
ledger_ast(thread_t thread)
{
	struct ledger *l = thread->t_ledger;
	struct ledger  *thl = thread->t_threadledger;
	uint32_t block;
	uint64_t now;
	kern_return_t ret;
	task_t task = thread->task;

	lprintf(("Ledger AST for %p\n", thread));

	ASSERT(task != NULL);
	ASSERT(thread == current_thread());

top:
	/*
	 * Make sure this thread is up to date with regards to any task-wide per-thread
	 * CPU limit.
	 */
	if ((task->rusage_cpu_flags & TASK_RUSECPU_FLAGS_PERTHR_LIMIT) &&
	    ((thread->options & TH_OPT_PROC_CPULIMIT) == 0) ) {
		/*
		 * Task has a per-thread CPU limit on it, and this thread
		 * needs it applied.
		 */
		thread_set_cpulimit(THREAD_CPULIMIT_EXCEPTION, task->rusage_cpu_perthr_percentage,
			task->rusage_cpu_perthr_interval);
		assert((thread->options & TH_OPT_PROC_CPULIMIT) != 0);
	} else if (((task->rusage_cpu_flags & TASK_RUSECPU_FLAGS_PERTHR_LIMIT) == 0) &&
		    (thread->options & TH_OPT_PROC_CPULIMIT)) {
		/*
		 * Task no longer has a per-thread CPU limit; remove this thread's
		 * corresponding CPU limit.
		 */
		thread_set_cpulimit(THREAD_CPULIMIT_EXCEPTION, 0, 0);
		assert((thread->options & TH_OPT_PROC_CPULIMIT) == 0);
	}

	/*
	 * If the task or thread is being terminated, let's just get on with it
	 */
	if ((l == NULL) || !task->active || task->halting || !thread->active)
		return;
	
	/*
	 * Examine all entries in deficit to see which might be eligble for
	 * an automatic refill, which require callbacks to be issued, and
	 * which require blocking.
	 */
	block = 0;
	now = mach_absolute_time();

	if (LEDGER_VALID(thl)) {
		block |= ledger_check_needblock(thl, now);
	}
	block |= ledger_check_needblock(l, now);

	/*
	 * If we are supposed to block on the availability of one or more
	 * resources, find the first entry in deficit for which we should wait.
	 * Schedule a refill if necessary and then sleep until the resource
	 * becomes available.
	 */
	if (block) {
		if (LEDGER_VALID(thl)) {
			ret = ledger_perform_blocking(thl);
			if (ret != KERN_SUCCESS)
				goto top;
		}
		ret = ledger_perform_blocking(l);
		if (ret != KERN_SUCCESS)
			goto top;
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
		if (limit_exceeded(le) == FALSE)
			continue;

		/* Check for refill eligibility */
		if (le->le_refill_period) {
			if ((le->le_last_refill + le->le_refill_period) > now) {
				ledger_refill(now, l, i);
				if (limit_exceeded(le) == FALSE)
					continue;
			}
		}

		if (le->le_flags & LEDGER_ACTION_BLOCK)
			block = 1;
		if ((le->le_flags & LEDGER_ACTION_CALLBACK) == 0)
			continue;
		lc = entry_get_callback(l, i);
		assert(lc != NULL);
		flags = flag_set(&le->le_flags, CALLED_BACK);
		/* Callback has already been called */
		if (flags & CALLED_BACK)
			continue;
		lc->lc_func(lc->lc_param0, lc->lc_param1);
	}
	return(block);
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
		    ((le->le_flags & LEDGER_ACTION_BLOCK) == 0))
			continue;

		/* Prepare to sleep until the resource is refilled */
		ret = assert_wait_deadline(le, TRUE,
		    le->le_last_refill + le->le_refill_period);
		if (ret != THREAD_WAITING)
			return(KERN_SUCCESS);

		/* Mark that somebody is waiting on this entry  */
		flag_set(&le->le_flags, WAKE_NEEDED);

		ret = thread_block_reason(THREAD_CONTINUE_NULL, NULL,
		    AST_LEDGER);
		if (ret != THREAD_AWAKENED)
			return(KERN_SUCCESS);

		/*
		 * The world may have changed while we were asleep.
		 * Some other resource we need may have gone into
		 * deficit.  Or maybe we're supposed to die now.
		 * Go back to the top and reevaluate.
		 */
		return(KERN_FAILURE);
	}
	return(KERN_SUCCESS);
}


kern_return_t
ledger_get_entries(ledger_t ledger, int entry, ledger_amount_t *credit,
    ledger_amount_t *debit)
{
	struct ledger_entry *le;

	if (!ENTRY_VALID(ledger, entry))
		return (KERN_INVALID_ARGUMENT);

	le = &ledger->l_entries[entry];

	*credit = le->le_credit;
	*debit = le->le_debit;

	return (KERN_SUCCESS);
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
	if ((*len < 0) || (l == NULL))
		return (EINVAL);

	if (*len > l->l_size)
		 *len = l->l_size;
	lti = kalloc((*len) * sizeof (struct ledger_template_info));
	if (lti == NULL)
		return (ENOMEM);
	*buf = lti;

	template_lock(l->l_template);
	et = l->l_template->lt_entries;

	for (i = 0; i < *len; i++) {
		memset(lti, 0, sizeof (*lti));
		strlcpy(lti->lti_name, et->et_key, LEDGER_NAME_MAX);
		strlcpy(lti->lti_group, et->et_group, LEDGER_NAME_MAX);
		strlcpy(lti->lti_units, et->et_units, LEDGER_NAME_MAX);
		et++;
		lti++;
	}
	template_unlock(l->l_template);

	return (0);
}

int
ledger_entry_info(task_t task, void **buf, int *len)
{
	struct ledger_entry_info *lei;
	struct ledger_entry *le;
	uint64_t now = mach_absolute_time();
	int i;
	ledger_t l;

	if ((*len < 0) || ((l = task->ledger) == NULL))
		return (EINVAL);

	if (*len > l->l_size)
		 *len = l->l_size;
	lei = kalloc((*len) * sizeof (struct ledger_entry_info));
	if (lei == NULL)
		return (ENOMEM);
	*buf = lei;

	le = l->l_entries;

	for (i = 0; i < *len; i++) {
		memset(lei, 0, sizeof (*lei));
		lei->lei_limit = le->le_limit;
		lei->lei_credit = le->le_credit;
		lei->lei_debit = le->le_debit;
		lei->lei_balance = lei->lei_credit - lei->lei_debit;
		lei->lei_refill_period =
			abstime_to_nsecs(le->le_refill_period);
		lei->lei_last_refill =
			abstime_to_nsecs(now - le->le_last_refill);
		le++;
		lei++;
	}

	return (0);
}

int
ledger_info(task_t task, struct ledger_info *info)
{
	ledger_t l;

	if ((l = task->ledger) == NULL)
		return (ENOENT);

	memset(info, 0, sizeof (*info));

	strlcpy(info->li_name, l->l_template->lt_name, LEDGER_NAME_MAX);
	info->li_id = l->l_id;
	info->li_entries = l->l_size;
	return (0);
}

#ifdef LEDGER_DEBUG
int
ledger_limit(task_t task, struct ledger_limit_args *args)
{
	ledger_t l;
	int64_t limit;
	int idx;

	if ((l = task->ledger) == NULL)
		return (EINVAL);

	idx = ledger_key_lookup(l->l_template, args->lla_name);
	if ((idx < 0) || (idx >= l->l_size))
		return (EINVAL);

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

	if (args->lla_refill_period > 0)
		ledger_set_period(l, idx, args->lla_refill_period);

	ledger_set_limit(l, idx, limit);
	flag_set(&l->l_entries[idx].le_flags, LEDGER_ACTION_BLOCK);
	return (0);
}
#endif
