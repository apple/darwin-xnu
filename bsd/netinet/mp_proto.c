/*
 * Copyright (c) 2012 Apple Inc. All rights reserved.
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

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/mcache.h>

#include <kern/locks.h>

#include <netinet/in.h>
#if MPTCP
#include <netinet/mptcp_var.h>
#endif /* MPTCP */

extern struct domain mpdomain_s;
static struct domain *mpdomain = NULL;

static void mp_dinit(struct domain *);
lck_mtx_t *mp_domain_mutex;

static struct protosw mpsw[] = {
#if MPTCP
{
	.pr_type =		SOCK_STREAM,
	.pr_protocol =		IPPROTO_TCP,
	.pr_flags =		PR_CONNREQUIRED|PR_MULTICONN|PR_EVCONNINFO|
				PR_WANTRCVD|PR_PCBLOCK|PR_PROTOLOCK|
				PR_PRECONN_WRITE|PR_DATA_IDEMPOTENT,
	.pr_ctloutput =		mptcp_ctloutput,
	.pr_init =		mptcp_init,
	.pr_usrreqs =		&mptcp_usrreqs,
	.pr_lock =		mptcp_lock,
	.pr_unlock =		mptcp_unlock,
	.pr_getlock =		mptcp_getlock,
},
#endif /* MPTCP */
};

static int mp_proto_count = (sizeof (mpsw) / sizeof (struct protosw));

struct domain mpdomain_s = {
	.dom_family =		PF_MULTIPATH,
	.dom_flags =		DOM_REENTRANT,
	.dom_name =		"multipath",
	.dom_init =		mp_dinit,
};

/* Initialize the PF_MULTIPATH domain, and add in the pre-defined protos */
void
mp_dinit(struct domain *dp)
{
	struct protosw *pr;
	int i;

	VERIFY(!(dp->dom_flags & DOM_INITIALIZED));
	VERIFY(mpdomain == NULL);

	mpdomain = dp;

	for (i = 0, pr = &mpsw[0]; i < mp_proto_count; i++, pr++)
		net_add_proto(pr, dp, 1);

	mp_domain_mutex = dp->dom_mtx;
}
