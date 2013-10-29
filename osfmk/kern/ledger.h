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

#ifndef _KERN_LEDGER_H_
#define _KERN_LEDGER_H_

#define	LEDGER_INFO		0
#define	LEDGER_ENTRY_INFO	1
#define	LEDGER_TEMPLATE_INFO	2
#define	LEDGER_LIMIT		3

#define	LEDGER_NAME_MAX	32

struct ledger_info {
	char	li_name[LEDGER_NAME_MAX];
	int64_t	li_id;
	int64_t	li_entries;
};

struct ledger_template_info {
	char		lti_name[LEDGER_NAME_MAX];
	char		lti_group[LEDGER_NAME_MAX];
	char		lti_units[LEDGER_NAME_MAX];
};

struct ledger_entry_info {
        int64_t		lei_balance;
        int64_t		lei_credit;
        int64_t		lei_debit;
        uint64_t	lei_limit;
	uint64_t	lei_refill_period;	/* In milliseconds */
	uint64_t	lei_last_refill;	/* Time since last refill */
};

struct ledger_limit_args {
	char		lla_name[LEDGER_NAME_MAX];
        uint64_t	lla_limit;
        uint64_t	lla_refill_period;
};

#ifdef	KERNEL_PRIVATE

typedef struct ledger_template *ledger_template_t;

#define	LEDGER_VALID(ledger)	(ledger != LEDGER_NULL)

/* Action to take when a ledger goes into deficit */
#define	LEDGER_ACTION_IGNORE	0x0000
#define	LEDGER_ACTION_BLOCK	0x0010
#define	LEDGER_ACTION_CALLBACK	0x0020
#define	LEDGER_ACTION_MASK	0x00f0

/*
 * Types of warnings that trigger a callback.
 */
#define	LEDGER_WARNING_ROSE_ABOVE	1
#define	LEDGER_WARNING_DIPPED_BELOW	2

typedef void (*ledger_callback_t)(int warning, const void * param0, const void *param1);

extern void ledger_init(void);

extern ledger_template_t ledger_template_create(const char *name);
extern void ledger_template_dereference(ledger_template_t template);
extern int ledger_entry_add(ledger_template_t template, const char *key,
    const char *group, const char *units);
extern kern_return_t ledger_set_callback(ledger_template_t template, int entry,
	ledger_callback_t callback, const void *param0, const void *param1);
extern kern_return_t ledger_track_maximum(ledger_template_t template, int entry,
	int period_in_secs);
extern int ledger_key_lookup(ledger_template_t template, const char *key);

/* value of entry type */
#define	LEDGER_CREATE_ACTIVE_ENTRIES	0
#define	LEDGER_CREATE_INACTIVE_ENTRIES	1
extern ledger_t ledger_instantiate(ledger_template_t template, int entry_type);
extern kern_return_t ledger_disable_callback(ledger_t ledger, int entry);
extern kern_return_t ledger_enable_callback(ledger_t ledger, int entry);
extern kern_return_t ledger_get_limit(ledger_t ledger, int entry,
	ledger_amount_t *limit);
extern kern_return_t ledger_set_limit(ledger_t ledger, int entry,
	ledger_amount_t limit, uint8_t warn_level_percentage);
extern kern_return_t ledger_get_maximum(ledger_t ledger, int entry,
	ledger_amount_t *max_observed_balance);
extern kern_return_t ledger_get_actions(ledger_t ledger, int entry, int *actions);
extern kern_return_t ledger_set_action(ledger_t ledger, int entry, int action);
extern kern_return_t ledger_get_period(ledger_t ledger, int entry,
    uint64_t *period);
extern kern_return_t ledger_set_period(ledger_t ledger, int entry,
    uint64_t period);
extern kern_return_t ledger_disable_refill(ledger_t l, int entry);
extern kern_return_t ledger_entry_setactive(ledger_t ledger, int entry);
extern kern_return_t ledger_credit(ledger_t ledger, int entry,
	ledger_amount_t amount);
extern kern_return_t ledger_debit(ledger_t ledger, int entry,
	ledger_amount_t amount);
extern kern_return_t ledger_zero_balance(ledger_t ledger, int entry);
extern kern_return_t ledger_get_entries(ledger_t ledger, int entry,
	ledger_amount_t *credit, ledger_amount_t *debit);
extern kern_return_t ledger_get_balance(ledger_t ledger, int entry,
	ledger_amount_t *balance);

extern void ledger_ast(thread_t thread);
extern void set_astledger(thread_t thread);

extern int ledger_reference_count(ledger_t ledger);
extern kern_return_t ledger_reference(ledger_t ledger);
extern kern_return_t ledger_dereference(ledger_t ledger);

/* Per-pmap ledger operations */
#define	pmap_ledger_debit(p, e, a) ledger_debit((p)->ledger, e, a)
#define	pmap_ledger_credit(p, e, a) ledger_credit((p)->ledger, e, a)

/* Support for ledger() syscall */
#ifdef LEDGER_DEBUG
extern int ledger_limit(task_t task, struct ledger_limit_args *args);
#endif
extern int ledger_info(task_t task, struct ledger_info *info);

extern int 
ledger_get_task_entry_info_multiple(task_t task, void **buf, int *len);

extern void
ledger_get_entry_info(ledger_t ledger, int entry,
                      struct ledger_entry_info *lei);

extern int ledger_template_info(void **buf, int *len);

#endif /* KERNEL_PRIVATE */

#endif	/* _KERN_LEDGER_H_ */
