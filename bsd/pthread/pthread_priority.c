/*
 * Copyright (c) 2017 Apple Inc. All rights reserved.
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
 *
 */

#include <pthread/priority_private.h>

#ifndef QOS_MIN_RELATIVE_PRIORITY // from <sys/qos.h> in userspace
#define QOS_MIN_RELATIVE_PRIORITY -15
#endif

pthread_priority_compact_t
_pthread_priority_normalize(pthread_priority_t pp)
{
	if (pp & _PTHREAD_PRIORITY_EVENT_MANAGER_FLAG) {
		return _PTHREAD_PRIORITY_EVENT_MANAGER_FLAG;
	}
	if (_pthread_priority_has_qos(pp)) {
		int relpri = _pthread_priority_relpri(pp);
		if (relpri > 0 || relpri < QOS_MIN_RELATIVE_PRIORITY) {
			pp |= _PTHREAD_PRIORITY_PRIORITY_MASK;
		}
		return pp & (_PTHREAD_PRIORITY_OVERCOMMIT_FLAG |
		       _PTHREAD_PRIORITY_FALLBACK_FLAG |
		       _PTHREAD_PRIORITY_QOS_CLASS_MASK |
		       _PTHREAD_PRIORITY_PRIORITY_MASK);
	}
	return _pthread_unspecified_priority();
}

pthread_priority_compact_t
_pthread_priority_normalize_for_ipc(pthread_priority_t pp)
{
	if (_pthread_priority_has_qos(pp)) {
		int relpri = _pthread_priority_relpri(pp);
		if (relpri > 0 || relpri < QOS_MIN_RELATIVE_PRIORITY) {
			pp |= _PTHREAD_PRIORITY_PRIORITY_MASK;
		}
		return pp & (_PTHREAD_PRIORITY_QOS_CLASS_MASK |
		       _PTHREAD_PRIORITY_PRIORITY_MASK);
	}
	return _pthread_unspecified_priority();
}

pthread_priority_compact_t
_pthread_priority_combine(pthread_priority_t base_pp, thread_qos_t qos)
{
	if (base_pp & _PTHREAD_PRIORITY_EVENT_MANAGER_FLAG) {
		return _PTHREAD_PRIORITY_EVENT_MANAGER_FLAG;
	}

	if (base_pp & _PTHREAD_PRIORITY_FALLBACK_FLAG) {
		if (!qos) {
			return (pthread_priority_compact_t)base_pp;
		}
	} else if (qos < _pthread_priority_thread_qos(base_pp)) {
		return (pthread_priority_compact_t)base_pp;
	}

	return _pthread_priority_make_from_thread_qos(qos, 0,
	           base_pp & _PTHREAD_PRIORITY_OVERCOMMIT_FLAG);
}
