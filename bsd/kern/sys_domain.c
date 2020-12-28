/*
 * Copyright (c) 2000-2014 Apple Inc. All rights reserved.
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
/*
 *	@(#)sys_domain.c       1.0 (6/1/2000)
 */

#include <sys/param.h>
#include <sys/protosw.h>
#include <sys/domain.h>
#include <sys/mcache.h>
#include <sys/sys_domain.h>
#include <sys/sysctl.h>

struct domain *systemdomain = NULL;

/* domain init function */
static void systemdomain_init(struct domain *);

struct domain systemdomain_s = {
	.dom_family =           PF_SYSTEM,
	.dom_name =             "system",
	.dom_init =             systemdomain_init,
};

SYSCTL_NODE(_net, PF_SYSTEM, systm,
    CTLFLAG_RW | CTLFLAG_LOCKED, 0, "System domain");


static void
systemdomain_init(struct domain *dp)
{
	VERIFY(!(dp->dom_flags & DOM_INITIALIZED));
	VERIFY(systemdomain == NULL);

	systemdomain = dp;

	/* add system domain built in protocol initializers here */
	kern_event_init(dp);
	kern_control_init(dp);
}
