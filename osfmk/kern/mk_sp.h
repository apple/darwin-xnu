/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
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
 * Scheduling operation prototypes
 */

void		_mk_sp_thread_unblock(
				thread_t		thread);

void		_mk_sp_thread_done(
				thread_t		old_thread,
				thread_t		new_thread,
				processor_t		processor);

void		_mk_sp_thread_begin(
				thread_t		new_thread,
				processor_t		processor);

void		_mk_sp_thread_dispatch(
				thread_t		thread);

kern_return_t	_mk_sp_thread_switch(
					thread_act_t		hint_act,
					int					option,
					mach_msg_timeout_t	option_time);

void		_mk_sp_thread_depress_ms(
				mach_msg_timeout_t		interval);

void		_mk_sp_thread_depress_abstime(
				uint64_t				interval);

kern_return_t	_mk_sp_thread_depress_abort(
					thread_t			thread,
					boolean_t			abortall);

void		_mk_sp_thread_perhaps_yield(
				thread_t				self);

#endif	/* _KERN_MK_SP_H_ */
