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
/* Copyright (C) 1999 Apple Computer, Inc.  */

/*
 * Support for Network Kernel Extensions: Socket Filters
 *
 * Justin C. Walker, 990319
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/malloc.h>
#include <sys/param.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <machine/spl.h>
#include "kext_net.h"

/* List of kernel extensions (networking) known to kernel */
struct nf_list nf_list;

/*
 * Register a global filter for the specified protocol
 * Make a few checks and then insert the new descriptor in the
 *  filter list and, if global, in its protosw's chain.
 */
int
register_sockfilter(struct NFDescriptor *nfp, struct NFDescriptor *nfp1,
		    struct protosw *pr, int flags)
{	int s;
	static int NF_initted = 0;

	if (nfp == NULL)
		return(EINVAL);

	s = splhigh();
	if (!NF_initted)
	{	NF_initted = 1;
		TAILQ_INIT(&nf_list);
	}

	/*
	 * Install the extension:
	 * First, put it in the global list of all filters
	 * Then, if global, install in the protosw's list 
	 */
	TAILQ_INSERT_TAIL(&nf_list, nfp, nf_list);
	if (nfp->nf_flags & NFD_GLOBAL)
	{	if (flags & NFF_BEFORE)
		{	if (nfp1 == NULL)
			{	TAILQ_INSERT_HEAD(&pr->pr_sfilter,
						  nfp, nf_next);
			} else
				TAILQ_INSERT_BEFORE(nfp1, nfp, nf_next);
		} else		/* Default: AFTER */
		{	if (nfp1 == NULL)
			{	TAILQ_INSERT_TAIL(&pr->pr_sfilter,
						  nfp, nf_next);
			} else
				TAILQ_INSERT_AFTER(&pr->pr_sfilter, nfp1,
						   nfp, nf_next);
		}
	}
	splx(s);
	return(0);
}

unregister_sockfilter(struct NFDescriptor *nfp, struct protosw *pr, int flags)
{	int s;

	s = splhigh();
	TAILQ_REMOVE(&nf_list, nfp, nf_list);
	/* Only globals are attached to the protosw entry */
	if (nfp->nf_flags & NFD_GLOBAL)
		TAILQ_REMOVE(&pr->pr_sfilter, nfp, nf_next);
	splx(s);
	return(0);
}

struct NFDescriptor *
find_nke(unsigned int handle)
{	struct NFDescriptor *nfp;

	nfp = nf_list.tqh_first;
	while (nfp)
	{	if (nfp->nf_handle == handle)
			return(nfp);
		nfp = nfp->nf_list.tqe_next;
	}
	return(NULL);
}

/*
 * Insert a previously registered, non-global, NKE into the list of
 *  active NKEs for this socket.  Then invoke its "attach/create" entry.
 * Assumed called with protection in place (spl/mutex/whatever)
 * XXX: How to which extension is not found, on error.
 */
int
nke_insert(struct socket *so, struct so_nke *np)
{	int s, error;
	struct kextcb *kp, *kp1;
	struct NFDescriptor *nf1, *nf2 = NULL;

	if (np->nke_where != NULL)
	{	if ((nf2 = find_nke(np->nke_where)) == NULL)
		{	/* ??? */
			return(ENXIO);/* XXX */
		}
	}

	if ((nf1 = find_nke(np->nke_handle)) == NULL)
	{	/* ??? */
		return(ENXIO);/* XXX */
	}

	kp = so->so_ext;
	kp1 = NULL;
        if (np->nke_flags & NFF_BEFORE)
	{	if (nf2)
		{       while (kp)
			{       if (kp->e_nfd == nf2)
					break;
				kp1 = kp;
				kp = kp->e_next;
			}
			if (kp == NULL)
				return(ENXIO);/* XXX */
		}
	} else
	{	if (nf2)
		{       while (kp)
			{       if (kp->e_nfd == nf2)
					break;
				kp1 = kp;
				kp = kp->e_next;
			}
			if (kp == NULL)
				return(ENXIO);/* XXX */
		}
		kp1 = kp;
	}
	/*
	 * Here with kp1 pointing to the insertion point.
	 * If null, this is first entry.
	 * Now, create and insert the descriptor.
	 */

	MALLOC(kp, struct kextcb *, sizeof(*kp), M_TEMP, M_WAITOK);
	if (kp == NULL)
		return(ENOBUFS); /* so_free will clean up */
	bzero(kp, sizeof (*kp));
	if (kp1 == NULL)
        {       kp->e_next = so->so_ext;
		so->so_ext = kp;
	} else
	{	kp->e_next = kp1->e_next;
		kp1->e_next = kp;
	}
	kp->e_fcb = NULL;
	kp->e_nfd = nf1;
	kp->e_soif = nf1->nf_soif;
	kp->e_sout = nf1->nf_soutil;
	/*
	 * Ignore return value for create
	 * Everyone gets a chance at startup
	 */
	if (kp->e_soif && kp->e_soif->sf_socreate)
		(*kp->e_soif->sf_socreate)(so, so->so_proto, kp);
	return(0);
}
