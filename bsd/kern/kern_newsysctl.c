/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
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
/*-
 * Copyright (c) 1982, 1986, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Mike Karels at Berkeley Software Design, Inc.
 *
 * Quite extensively rewritten by Poul-Henning Kamp of the FreeBSD
 * project, to make these variables more userfriendly.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)kern_sysctl.c	8.4 (Berkeley) 4/14/94
 */


#include <sys/param.h>
#include <sys/buf.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/systm.h>

#include <bsm/audit_kernel.h>

/*
struct sysctl_oid_list sysctl__debug_children;
struct sysctl_oid_list sysctl__kern_children;
struct sysctl_oid_list sysctl__net_children;
struct sysctl_oid_list sysctl__sysctl_children;
*/

extern struct sysctl_oid *newsysctl_list[];
extern struct sysctl_oid *machdep_sysctl_list[];


static void
sysctl_sysctl_debug_dump_node(struct sysctl_oid_list *l, int i);



/*
 * Locking and stats
 */
static struct sysctl_lock {
	int	sl_lock;
	int	sl_want;
	int	sl_locked;
} memlock;

/*
 * XXX this does not belong here
 */
static funnel_t *
spl_kernel_funnel(void)
{
	funnel_t *cfunnel;

	cfunnel = thread_funnel_get();
	if (cfunnel != kernel_flock) {
		if (cfunnel != NULL)
			thread_funnel_set(cfunnel, FALSE);
		thread_funnel_set(kernel_flock, TRUE);
	}
	return(cfunnel);
}

static void
splx_kernel_funnel(funnel_t *saved)
{
	if (saved != kernel_flock) {
		thread_funnel_set(kernel_flock, FALSE);
		if (saved != NULL) 
			thread_funnel_set(saved, TRUE);
	}
}

static int sysctl_root SYSCTL_HANDLER_ARGS;

struct sysctl_oid_list sysctl__children; /* root list */

/*
 * Initialization of the MIB tree.
 *
 * Order by number in each list.
 */

void sysctl_register_oid(struct sysctl_oid *oidp)
{
	struct sysctl_oid_list *parent = oidp->oid_parent;
	struct sysctl_oid *p;
	struct sysctl_oid *q;
	int n;
	funnel_t *fnl;

	fnl = spl_kernel_funnel();

	/*
	 * If this oid has a number OID_AUTO, give it a number which
	 * is greater than any current oid.  Make sure it is at least
	 * 100 to leave space for pre-assigned oid numbers.
	 */
/*	sysctl_sysctl_debug_dump_node(parent, 3); */
	if (oidp->oid_number == OID_AUTO) {
		/* First, find the highest oid in the parent list >99 */
		n = 99;
		SLIST_FOREACH(p, parent, oid_link) {
			if (p->oid_number > n)
				n = p->oid_number;
		}
		oidp->oid_number = n + 1;
	}

	/*
	 * Insert the oid into the parent's list in order.
	 */
	q = NULL;
	SLIST_FOREACH(p, parent, oid_link) {
		if (oidp->oid_number < p->oid_number)
			break;
		q = p;
	}
	if (q)
		SLIST_INSERT_AFTER(q, oidp, oid_link);
	else
		SLIST_INSERT_HEAD(parent, oidp, oid_link);

	splx_kernel_funnel(fnl);
}

void sysctl_unregister_oid(struct sysctl_oid *oidp)
{
	funnel_t *fnl;

	fnl = spl_kernel_funnel();
	SLIST_REMOVE(oidp->oid_parent, oidp, sysctl_oid, oid_link);
	splx_kernel_funnel(fnl);
}

/*
 * Bulk-register all the oids in a linker_set.
 */
void sysctl_register_set(struct linker_set *lsp)
{
	int count = lsp->ls_length;
	int i;
	for (i = 0; i < count; i++)
		sysctl_register_oid((struct sysctl_oid *) lsp->ls_items[i]);
}

void sysctl_unregister_set(struct linker_set *lsp)
{
	int count = lsp->ls_length;
	int i;
	for (i = 0; i < count; i++)
		sysctl_unregister_oid((struct sysctl_oid *) lsp->ls_items[i]);
}


/*
 * Register OID's from fixed list
 */

void sysctl_register_fixed()
{
    int i;

    for (i=0; newsysctl_list[i]; i++) {
	sysctl_register_oid(newsysctl_list[i]);
    }
    for (i=0; machdep_sysctl_list[i]; i++) {
	sysctl_register_oid(machdep_sysctl_list[i]);
    }
}

/*
 * Register the kernel's oids on startup.
 */
struct linker_set sysctl_set;

void sysctl_register_all(void *arg)
{
	sysctl_register_set(&sysctl_set);
}

SYSINIT(sysctl, SI_SUB_KMEM, SI_ORDER_ANY, sysctl_register_all, 0);

/*
 * "Staff-functions"
 *
 * These functions implement a presently undocumented interface 
 * used by the sysctl program to walk the tree, and get the type
 * so it can print the value.
 * This interface is under work and consideration, and should probably
 * be killed with a big axe by the first person who can find the time.
 * (be aware though, that the proper interface isn't as obvious as it
 * may seem, there are various conflicting requirements.
 *
 * {0,0}	printf the entire MIB-tree.
 * {0,1,...}	return the name of the "..." OID.
 * {0,2,...}	return the next OID.
 * {0,3}	return the OID of the name in "new"
 * {0,4,...}	return the kind & format info for the "..." OID.
 */

static void
sysctl_sysctl_debug_dump_node(struct sysctl_oid_list *l, int i)
{
	int k;
	struct sysctl_oid *oidp;

	SLIST_FOREACH(oidp, l, oid_link) {

		for (k=0; k<i; k++)
			printf(" ");

		printf("%d %s ", oidp->oid_number, oidp->oid_name);

		printf("%c%c",
			oidp->oid_kind & CTLFLAG_RD ? 'R':' ',
			oidp->oid_kind & CTLFLAG_WR ? 'W':' ');

		if (oidp->oid_handler)
			printf(" *Handler");

		switch (oidp->oid_kind & CTLTYPE) {
			case CTLTYPE_NODE:
				printf(" Node\n");
				if (!oidp->oid_handler) {
					sysctl_sysctl_debug_dump_node(
						oidp->oid_arg1, i+2);
				}
				break;
			case CTLTYPE_INT:    printf(" Int\n"); break;
			case CTLTYPE_STRING: printf(" String\n"); break;
			case CTLTYPE_QUAD:   printf(" Quad\n"); break;
			case CTLTYPE_OPAQUE: printf(" Opaque/struct\n"); break;
			default:	     printf("\n");
		}

	}
}

static int
sysctl_sysctl_debug SYSCTL_HANDLER_ARGS
{
	sysctl_sysctl_debug_dump_node(&sysctl__children, 0);
	return ENOENT;
}

SYSCTL_PROC(_sysctl, 0, debug, CTLTYPE_STRING|CTLFLAG_RD,
	0, 0, sysctl_sysctl_debug, "-", "");

static int
sysctl_sysctl_name SYSCTL_HANDLER_ARGS
{
	int *name = (int *) arg1;
	u_int namelen = arg2;
	int error = 0;
	struct sysctl_oid *oid;
	struct sysctl_oid_list *lsp = &sysctl__children, *lsp2;
	char buf[10];

	while (namelen) {
		if (!lsp) {
			snprintf(buf,sizeof(buf),"%d",*name);
			if (req->oldidx)
				error = SYSCTL_OUT(req, ".", 1);
			if (!error)
				error = SYSCTL_OUT(req, buf, strlen(buf));
			if (error)
				return (error);
			namelen--;
			name++;
			continue;
		}
		lsp2 = 0;
		SLIST_FOREACH(oid, lsp, oid_link) {
			if (oid->oid_number != *name)
				continue;

			if (req->oldidx)
				error = SYSCTL_OUT(req, ".", 1);
			if (!error)
				error = SYSCTL_OUT(req, oid->oid_name,
					strlen(oid->oid_name));
			if (error)
				return (error);

			namelen--;
			name++;

			if ((oid->oid_kind & CTLTYPE) != CTLTYPE_NODE) 
				break;

			if (oid->oid_handler)
				break;

			lsp2 = (struct sysctl_oid_list *)oid->oid_arg1;
			break;
		}
		lsp = lsp2;
	}
	return (SYSCTL_OUT(req, "", 1));
}

SYSCTL_NODE(_sysctl, 1, name, CTLFLAG_RD, sysctl_sysctl_name, "");

static int
sysctl_sysctl_next_ls (struct sysctl_oid_list *lsp, int *name, u_int namelen, 
	int *next, int *len, int level, struct sysctl_oid **oidpp)
{
	struct sysctl_oid *oidp;

	*len = level;
	SLIST_FOREACH(oidp, lsp, oid_link) {
		*next = oidp->oid_number;
		*oidpp = oidp;

		if (!namelen) {
			if ((oidp->oid_kind & CTLTYPE) != CTLTYPE_NODE) 
				return 0;
			if (oidp->oid_handler) 
				/* We really should call the handler here...*/
				return 0;
			lsp = (struct sysctl_oid_list *)oidp->oid_arg1;
			if (!sysctl_sysctl_next_ls (lsp, 0, 0, next+1, 
				len, level+1, oidpp))
				return 0;
			goto next;
		}

		if (oidp->oid_number < *name)
			continue;

		if (oidp->oid_number > *name) {
			if ((oidp->oid_kind & CTLTYPE) != CTLTYPE_NODE)
				return 0;
			if (oidp->oid_handler)
				return 0;
			lsp = (struct sysctl_oid_list *)oidp->oid_arg1;
			if (!sysctl_sysctl_next_ls (lsp, name+1, namelen-1, 
				next+1, len, level+1, oidpp))
				return (0);
			goto next;
		}
		if ((oidp->oid_kind & CTLTYPE) != CTLTYPE_NODE)
			continue;

		if (oidp->oid_handler)
			continue;

		lsp = (struct sysctl_oid_list *)oidp->oid_arg1;
		if (!sysctl_sysctl_next_ls (lsp, name+1, namelen-1, next+1, 
			len, level+1, oidpp))
			return (0);
	next:
		namelen = 1;
		*len = level;
	}
	return 1;
}

static int
sysctl_sysctl_next SYSCTL_HANDLER_ARGS
{
	int *name = (int *) arg1;
	u_int namelen = arg2;
	int i, j, error;
	struct sysctl_oid *oid;
	struct sysctl_oid_list *lsp = &sysctl__children;
	int newoid[CTL_MAXNAME];

	i = sysctl_sysctl_next_ls (lsp, name, namelen, newoid, &j, 1, &oid);
	if (i)
		return ENOENT;
	error = SYSCTL_OUT(req, newoid, j * sizeof (int));
	return (error);
}

SYSCTL_NODE(_sysctl, 2, next, CTLFLAG_RD, sysctl_sysctl_next, "");

static int
name2oid (char *name, int *oid, int *len, struct sysctl_oid **oidpp)
{
	int i;
	struct sysctl_oid *oidp;
	struct sysctl_oid_list *lsp = &sysctl__children;
	char *p;

	if (!*name)
		return ENOENT;

	p = name + strlen(name) - 1 ;
	if (*p == '.')
		*p = '\0';

	*len = 0;

	for (p = name; *p && *p != '.'; p++) 
		;
	i = *p;
	if (i == '.')
		*p = '\0';

	oidp = SLIST_FIRST(lsp);

	while (oidp && *len < CTL_MAXNAME) {
		if (strcmp(name, oidp->oid_name)) {
			oidp = SLIST_NEXT(oidp, oid_link);
			continue;
		}
		*oid++ = oidp->oid_number;
		(*len)++;

		if (!i) {
			if (oidpp)
				*oidpp = oidp;
			return (0);
		}

		if ((oidp->oid_kind & CTLTYPE) != CTLTYPE_NODE)
			break;

		if (oidp->oid_handler)
			break;

		lsp = (struct sysctl_oid_list *)oidp->oid_arg1;
		oidp = SLIST_FIRST(lsp);
		name = p+1;
		for (p = name; *p && *p != '.'; p++) 
				;
		i = *p;
		if (i == '.')
			*p = '\0';
	}
	return ENOENT;
}

static int
sysctl_sysctl_name2oid SYSCTL_HANDLER_ARGS
{
	char *p;
	int error, oid[CTL_MAXNAME], len;
	struct sysctl_oid *op = 0;

	if (!req->newlen) 
		return ENOENT;
	if (req->newlen >= MAXPATHLEN)	/* XXX arbitrary, undocumented */
		return (ENAMETOOLONG);

	p = _MALLOC(req->newlen+1, M_TEMP, M_WAITOK);

	if (!p)
	    return ENOMEM;

	error = SYSCTL_IN(req, p, req->newlen);
	if (error) {
		FREE(p, M_TEMP);
		return (error);
	}

	p [req->newlen] = '\0';

	error = name2oid(p, oid, &len, &op);

	FREE(p, M_TEMP);

	if (error)
		return (error);

	error = SYSCTL_OUT(req, oid, len * sizeof *oid);
	return (error);
}

SYSCTL_PROC(_sysctl, 3, name2oid, CTLFLAG_RW|CTLFLAG_ANYBODY|CTLFLAG_KERN, 0, 0, 
	sysctl_sysctl_name2oid, "I", "");

static int
sysctl_sysctl_oidfmt SYSCTL_HANDLER_ARGS
{
	int *name = (int *) arg1, error;
	u_int namelen = arg2;
	int indx;
	struct sysctl_oid *oid;
	struct sysctl_oid_list *lsp = &sysctl__children;

	oid = SLIST_FIRST(lsp);

	indx = 0;
	while (oid && indx < CTL_MAXNAME) {
		if (oid->oid_number == name[indx]) {
			indx++;
			if ((oid->oid_kind & CTLTYPE) == CTLTYPE_NODE) {
				if (oid->oid_handler)
					goto found;
				if (indx == namelen)
					goto found;
				lsp = (struct sysctl_oid_list *)oid->oid_arg1;
				oid = SLIST_FIRST(lsp);
			} else {
				if (indx != namelen)
					return EISDIR;
				goto found;
			}
		} else {
			oid = SLIST_NEXT(oid, oid_link);
		}
	}
	return ENOENT;
found:
	if (!oid->oid_fmt)
		return ENOENT;
	error = SYSCTL_OUT(req, 
		&oid->oid_kind, sizeof(oid->oid_kind));
	if (!error)
		error = SYSCTL_OUT(req, oid->oid_fmt, 
			strlen(oid->oid_fmt)+1);
	return (error);
}


SYSCTL_NODE(_sysctl, 4, oidfmt, CTLFLAG_RD, sysctl_sysctl_oidfmt, "");

/*
 * Default "handler" functions.
 */

/*
 * Handle an int, signed or unsigned.
 * Two cases:
 *     a variable:  point arg1 at it.
 *     a constant:  pass it in arg2.
 */

int
sysctl_handle_int SYSCTL_HANDLER_ARGS
{
	int error = 0;

	if (arg1)
		error = SYSCTL_OUT(req, arg1, sizeof(int));
	else
		error = SYSCTL_OUT(req, &arg2, sizeof(int));

	if (error || !req->newptr)
		return (error);

	if (!arg1)
		error = EPERM;
	else
		error = SYSCTL_IN(req, arg1, sizeof(int));

	if (error == 0)
		AUDIT_ARG(value, *(int *)arg1);
	return (error);
}

/*
 * Handle a long, signed or unsigned.  arg1 points to it.
 */

int
sysctl_handle_long SYSCTL_HANDLER_ARGS
{
	int error = 0;

	if (!arg1)
		return (EINVAL);
	error = SYSCTL_OUT(req, arg1, sizeof(long));

	if (error || !req->newptr)
		return (error);

	error = SYSCTL_IN(req, arg1, sizeof(long));
	return (error);
}

/*
 * Handle a quad, signed or unsigned.  arg1 points to it.
 */

int
sysctl_handle_quad SYSCTL_HANDLER_ARGS
{
	int error = 0;

	if (!arg1)
		return (EINVAL);
	error = SYSCTL_OUT(req, arg1, sizeof(long long));

	if (error || !req->newptr)
		return (error);

	error = SYSCTL_IN(req, arg1, sizeof(long long));
	return (error);
}

/*
 * Expose an int value as a quad.
 *
 * This interface allows us to support interfaces defined
 * as using quad values while the implementation is still
 * using ints.
 */
int
sysctl_handle_int2quad SYSCTL_HANDLER_ARGS
{
	int error = 0;
	long long val;
	int newval;

	if (!arg1)
		return (EINVAL);
	val = (long long)*(int *)arg1;
	error = SYSCTL_OUT(req, &val, sizeof(long long));

	if (error || !req->newptr)
		return (error);

	error = SYSCTL_IN(req, &val, sizeof(long long));
	if (!error) {
		/*
		 * Value must be representable; check by
		 * casting and then casting back.
		 */
		newval = (int)val;
		if ((long long)newval != val) {
			error = ERANGE;
		} else {
			*(int *)arg1 = newval;
		}
	}
	return (error);
}

/*
 * Handle our generic '\0' terminated 'C' string.
 * Two cases:
 * 	a variable string:  point arg1 at it, arg2 is max length.
 * 	a constant string:  point arg1 at it, arg2 is zero.
 */

int
sysctl_handle_string SYSCTL_HANDLER_ARGS
{
	int error=0;

	error = SYSCTL_OUT(req, arg1, strlen((char *)arg1)+1);

	if (error || !req->newptr)
		return (error);

	if ((req->newlen - req->newidx) >= arg2) {
		error = EINVAL;
	} else {
		arg2 = (req->newlen - req->newidx);
		error = SYSCTL_IN(req, arg1, arg2);
		((char *)arg1)[arg2] = '\0';
	}

	return (error);
}

/*
 * Handle any kind of opaque data.
 * arg1 points to it, arg2 is the size.
 */

int
sysctl_handle_opaque SYSCTL_HANDLER_ARGS
{
	int error;

	error = SYSCTL_OUT(req, arg1, arg2);

	if (error || !req->newptr)
		return (error);

	error = SYSCTL_IN(req, arg1, arg2);

	return (error);
}

/*
 * Transfer functions to/from kernel space.
 */
static int
sysctl_old_kernel(struct sysctl_req *req, const void *p, size_t l)
{
	size_t i = 0;
	int error = 0;

	if (req->oldptr) {
		i = l;
		if (i > req->oldlen - req->oldidx)
			i = req->oldlen - req->oldidx;
		if (i > 0)
			bcopy((void*)p, (char *)req->oldptr + req->oldidx, i);
	}
	req->oldidx += l;
	if (req->oldptr && i != l)
		return (ENOMEM);
	return (0);
}

static int
sysctl_new_kernel(struct sysctl_req *req, void *p, size_t l)
{
	if (!req->newptr)
		return 0;
	if (req->newlen - req->newidx < l)
		return (EINVAL);
	bcopy((char *)req->newptr + req->newidx, p, l);
	req->newidx += l;
	return (0);
}

int
kernel_sysctl(struct proc *p, int *name, u_int namelen, void *old, size_t *oldlenp, void *new, size_t newlen)
{
	int error = 0;
	struct sysctl_req req;
	funnel_t *fnl;

	/*
	 * Construct request.
	 */
	bzero(&req, sizeof req);
	req.p = p;
	if (oldlenp)
		req.oldlen = *oldlenp;
	if (old)
		req.oldptr= old;
	if (newlen) {
		req.newlen = newlen;
		req.newptr = new;
	}
	req.oldfunc = sysctl_old_kernel;
	req.newfunc = sysctl_new_kernel;
	req.lock = 1;

	/*
	 * Locking.  Tree traversal always begins with the kernel funnel held.
	 */
	fnl = spl_kernel_funnel();

	/* XXX this should probably be done in a general way */
	while (memlock.sl_lock) {
		memlock.sl_want = 1;
		(void) tsleep((caddr_t)&memlock, PRIBIO+1, "sysctl", 0);
		memlock.sl_locked++;
	}
	memlock.sl_lock = 1;

	/* make the request */
	error = sysctl_root(0, name, namelen, &req);

	/* unlock memory if required */
	if (req.lock == 2)
		vsunlock(req.oldptr, req.oldlen, B_WRITE);

	memlock.sl_lock = 0;

	if (memlock.sl_want) {
		memlock.sl_want = 0;
		wakeup((caddr_t)&memlock);
	}

	/*
	 * Undo locking.
	 */
	splx_kernel_funnel(fnl);

	if (error && error != ENOMEM)
		return (error);

	if (oldlenp)
		*oldlenp = req.oldidx;

	return (error);
}

/*
 * Transfer function to/from user space.
 */
static int
sysctl_old_user(struct sysctl_req *req, const void *p, size_t l)
{
	int error = 0;
	size_t i = 0;

	if (req->oldptr) {
                if (req->oldlen - req->oldidx < l)
                    return (ENOMEM);
		i = l;
		if (i > req->oldlen - req->oldidx)
			i = req->oldlen - req->oldidx;
		if (i > 0)
			error = copyout((void*)p, (char *)req->oldptr + req->oldidx,
					i);
	}
	req->oldidx += l;
	if (error)
		return (error);
	if (req->oldptr && i < l)
		return (ENOMEM);
	return (0);
}

static int
sysctl_new_user(struct sysctl_req *req, void *p, size_t l)
{
	int error;

	if (!req->newptr)
		return 0;
	if (req->newlen - req->newidx < l)
		return (EINVAL);
	error = copyin((char *)req->newptr + req->newidx, p, l);
	req->newidx += l;
	return (error);
}

/*
 * Traverse our tree, and find the right node, execute whatever it points
 * at, and return the resulting error code.
 */

int
sysctl_root SYSCTL_HANDLER_ARGS
{
	int *name = (int *) arg1;
	u_int namelen = arg2;
	int indx, i;
	struct sysctl_oid *oid;
	struct sysctl_oid_list *lsp = &sysctl__children;
	int error;

	oid = SLIST_FIRST(lsp);

	indx = 0;
	while (oid && indx < CTL_MAXNAME) {
		if (oid->oid_number == name[indx]) {
			indx++;
			if (oid->oid_kind & CTLFLAG_NOLOCK)
				req->lock = 0;
			if ((oid->oid_kind & CTLTYPE) == CTLTYPE_NODE) {
				if (oid->oid_handler)
					goto found;
				if (indx == namelen)
					return ENOENT;
				lsp = (struct sysctl_oid_list *)oid->oid_arg1;
				oid = SLIST_FIRST(lsp);
			} else {
				if (indx != namelen)
					return EISDIR;
				goto found;
			}
		} else {
			oid = SLIST_NEXT(oid, oid_link);
		}
	}
	return ENOENT;
found:
	/* If writing isn't allowed */
	if (req->newptr && (!(oid->oid_kind & CTLFLAG_WR) ||
			    ((oid->oid_kind & CTLFLAG_SECURE) && securelevel > 0))) {
		return (EPERM);
	}

	/*
	 * If we're inside the kernel, the OID must be marked as kernel-valid.
	 * XXX This mechanism for testing is bad.
	 */
	if ((req->oldfunc == sysctl_old_kernel) && !(oid->oid_kind & CTLFLAG_KERN))
		return(EPERM);

	/* Most likely only root can write */
	if (!(oid->oid_kind & CTLFLAG_ANYBODY) &&
	    req->newptr && req->p &&
	    (error = suser(req->p->p_ucred, &req->p->p_acflag)))
		return (error);

	if (!oid->oid_handler) {
	    return EINVAL;
	}

	/*
	 * Switch to the NETWORK funnel for CTL_NET and KERN_IPC sysctls
	 */

	if (((name[0] == CTL_NET) || ((name[0] == CTL_KERN) &&
						       (name[1] == KERN_IPC))))
	     thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);

	if ((oid->oid_kind & CTLTYPE) == CTLTYPE_NODE) {
		i = (oid->oid_handler) (oid,
					name + indx, namelen - indx,
					req);
	} else {
		i = (oid->oid_handler) (oid,
					oid->oid_arg1, oid->oid_arg2,
					req);
	}

	/*
	 * Switch back to the KERNEL funnel, if necessary
	 */

	if (((name[0] == CTL_NET) || ((name[0] == CTL_KERN) &&
						       (name[1] == KERN_IPC))))
	     thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);

	return (i);
}

#ifndef _SYS_SYSPROTO_H_
struct sysctl_args {
	int	*name;
	u_int	namelen;
	void	*old;
	size_t	*oldlenp;
	void	*new;
	size_t	newlen;
};
#endif

int
/* __sysctl(struct proc *p, struct sysctl_args *uap) */
new_sysctl(struct proc *p, struct sysctl_args *uap)
{
	int error, i, name[CTL_MAXNAME];
	size_t j;

	if (uap->namelen > CTL_MAXNAME || uap->namelen < 2)
		return (EINVAL);

 	error = copyin(uap->name, &name, uap->namelen * sizeof(int));
 	if (error)
		return (error);

	error = userland_sysctl(p, name, uap->namelen,
		uap->old, uap->oldlenp, 0,
		uap->new, uap->newlen, &j);
	if (error && error != ENOMEM)
		return (error);
	if (uap->oldlenp) {
		i = copyout(&j, uap->oldlenp, sizeof(j));
		if (i)
			return (i);
	}
	return (error);
}

/*
 * This is used from various compatibility syscalls too.  That's why name
 * must be in kernel space.
 */
int
userland_sysctl(struct proc *p, int *name, u_int namelen, void *old, size_t *oldlenp, int inkernel, void *new, size_t newlen, size_t *retval)
{
	int error = 0;
	struct sysctl_req req, req2;

	bzero(&req, sizeof req);

	req.p = p;

	if (oldlenp) {
		if (inkernel) {
			req.oldlen = *oldlenp;
		} else {
			error = copyin(oldlenp, &req.oldlen, sizeof(*oldlenp));
			if (error)
				return (error);
		}
	}

	if (old) {
		req.oldptr= old;
	}

	if (newlen) {
		req.newlen = newlen;
		req.newptr = new;
	}

	req.oldfunc = sysctl_old_user;
	req.newfunc = sysctl_new_user;
	req.lock = 1;

	do {
	    req2 = req;
	    error = sysctl_root(0, name, namelen, &req2);
	} while (error == EAGAIN);

	req = req2;

	if (error && error != ENOMEM)
		return (error);

	if (retval) {
		if (req.oldptr && req.oldidx > req.oldlen)
			*retval = req.oldlen;
		else
			*retval = req.oldidx;
	}
	return (error);
}

/* Non-standard BSDI extension - only present on their 4.3 net-2 releases */
#define	KINFO_BSDI_SYSINFO	(101<<8)

/*
 * Kernel versions of the userland sysctl helper functions.
 *
 * These allow sysctl to be used in the same fashion in both
 * userland and the kernel.
 *
 * Note that some sysctl handlers use copyin/copyout, which
 * may not work correctly.
 */

static int
sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen)
{

	return(kernel_sysctl(current_proc(), name, namelen, oldp, oldlenp, newp, newlen));
}

static int
sysctlnametomib(const char *name, int *mibp, size_t *sizep)
{
	int oid[2];
	int error;

	/* magic service node */
	oid[0] = 0;
	oid[1] = 3;

	/* look up OID for name */
	*sizep *= sizeof(int);
	error = sysctl(oid, 2, mibp, sizep, (void *)name, strlen(name));
	*sizep /= sizeof(int);
	return(error);
}

int
sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen)
{
	int oid[CTL_MAXNAME + 2];
	int error;
	size_t oidlen;

	/* look up the OID */
	oidlen = CTL_MAXNAME;
	error = sysctlnametomib(name, oid, &oidlen);

	/* now use the OID */
	if (error == 0)
		error = sysctl(oid, oidlen, oldp, oldlenp, newp, newlen);
	return(error);
}

