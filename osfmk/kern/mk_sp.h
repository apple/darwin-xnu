/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 * 
 */

#ifndef	_KERN_MK_SP_H_
#define _KERN_MK_SP_H_

/*
* Include Files
*/

/*
 * Scheduling policy operation prototypes
 */

sf_return_t	_mk_sp_init(
				sf_object_t			policy,
				int					policy_id);

sf_return_t	_mk_sp_enable_processor_set(
				sf_object_t			policy,
				processor_set_t		processor_set);

sf_return_t	_mk_sp_disable_processor_set(
				sf_object_t			policy,
				processor_set_t		processor_set);

sf_return_t	_mk_sp_enable_processor(
				sf_object_t			policy,
				processor_t			processor);

sf_return_t	_mk_sp_disable_processor(
				sf_object_t			policy,
				processor_t			processor);

sf_return_t	_mk_sp_thread_update_mpri(
				sf_object_t			policy,
				thread_t			thread);

sf_return_t	_mk_sp_thread_unblock(
				sf_object_t			policy,
				thread_t			thread);

sf_return_t	_mk_sp_thread_done(
				sf_object_t			policy,
				thread_t			old_thread);

sf_return_t	_mk_sp_thread_begin(
				sf_object_t			policy,
				thread_t			new_thread);

sf_return_t	_mk_sp_thread_dispatch(
				sf_object_t			policy,
				thread_t			old_thread);

sf_return_t	_mk_sp_thread_attach(
				sf_object_t			policy,
				thread_t			thread);

sf_return_t	_mk_sp_thread_detach(
				sf_object_t			policy,
				thread_t			thread);

sf_return_t	_mk_sp_thread_processor(
				sf_object_t			policy,
				thread_t			*thread,
				processor_t			processor);

sf_return_t	_mk_sp_thread_processor_set(
				sf_object_t			policy,
				thread_t			thread,
				processor_set_t		processor_set);

sf_return_t	_mk_sp_thread_setup(
				sf_object_t			policy,
				thread_t			thread);

void		_mk_sp_swtch_pri(
				sf_object_t			policy,
				int					pri);

kern_return_t	_mk_sp_thread_switch(
					sf_object_t			policy,
					thread_act_t		hint_act,
					int					option,
					mach_msg_timeout_t	option_time);

kern_return_t	_mk_sp_thread_depress_abort(
					sf_object_t			policy,
					thread_t			thread);

void		_mk_sp_thread_depress_timeout(
					sf_object_t			policy,
					thread_t			thread);

boolean_t	_mk_sp_thread_runnable(
					sf_object_t			policy,
					thread_t			thread);

#define	MK_SP_ATTACHED	( 0x0001 )
#define	MK_SP_RUNNABLE	( 0x0002 )
#define	MK_SP_BLOCKED	( 0x0004 )

/*
 * Definitions of standard scheduling operations for this policy
 */
extern sp_ops_t		mk_sp_ops;

#endif	/* _KERN_MK_SP_H_ */
