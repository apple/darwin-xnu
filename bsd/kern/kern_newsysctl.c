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

/*
struct sysctl_oid_list sysctl__debug_children;
struct sysctl_oid_list sysctl__kern_children;
struct sysctl_oid_list sysctl__net_children;
struct sysctl_oid_list sysctl__sysctl_children;
*/

extern struct sysctl_oid *newsysctl_list[];


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
}

void sysctl_unregister_oid(struct sysctl_oid *oidp)
{
	SLIST_REMOVE(oidp->oid_parent, oidp, sysctl_oid, oid_link);
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
    int i = 0;


    while (newsysctl_list[i]) {
/*	printf("Registering %d\n", i); */
	sysctl_register_oid(newsysctl_list[i++]);
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

SYSCTL_PROC(_sysctl, 3, name2oid, CTLFLAG_RW|CTLFLAG_ANYBODY, 0, 0, 
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
 * XXX: rather untested at this point
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
		if (i > 0) {
			error = copyout((void*)p, (char *)req->oldptr + req->oldidx, i);
			if (error)
			    return error;
		}
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
	copyin((char *)req->newptr + req->newidx, p, l);
	req->newidx += l;
	return (0);
}

int
kernel_sysctl(struct proc *p, int *name, u_int namelen, void *old, size_t *oldlenp, void *new, size_t newlen, size_t *retval)
{
	int error = 0;
	struct sysctl_req req;

	bzero(&req, sizeof req);

	req.p = p;

	if (oldlenp) {
		req.oldlen = *oldlenp;
	}

	if (old) {
		req.oldptr= old;
	}

	if (newlen) {
		req.newlen = newlen;
		req.newptr = new;
	}

	req.oldfunc = sysctl_old_kernel;
	req.newfunc = sysctl_new_kernel;
	req.lock = 1;

	/* XXX this should probably be done in a general way */
	while (memlock.sl_lock) {
		memlock.sl_want = 1;
		(void) tsleep((caddr_t)&memlock, PRIBIO+1, "sysctl", 0);
		memlock.sl_locked++;
	}
	memlock.sl_lock = 1;

	error = sysctl_root(0, name, namelen, &req);

	if (req.lock == 2)
		vsunlock(req.oldptr, req.oldlen, B_WRITE);

	memlock.sl_lock = 0;

	if (memlock.sl_want) {
		memlock.sl_want = 0;
		wakeup((caddr_t)&memlock);
	}

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
#if 0

#if COMPAT_43
#include <sys/socket.h>
#include <vm/vm_param.h>

#define	KINFO_PROC		(0<<8)
#define	KINFO_RT		(1<<8)
#define	KINFO_VNODE		(2<<8)
#define	KINFO_FILE		(3<<8)
#define	KINFO_METER		(4<<8)
#define	KINFO_LOADAVG		(5<<8)
#define	KINFO_CLOCKRATE		(6<<8)

/* Non-standard BSDI extension - only present on their 4.3 net-2 releases */
#define	KINFO_BSDI_SYSINFO	(101<<8)

/*
 * XXX this is bloat, but I hope it's better here than on the potentially
 * limited kernel stack...  -Peter
 */

static struct {
	int	bsdi_machine;		/* "i386" on BSD/386 */
/*      ^^^ this is an offset to the string, relative to the struct start */
	char	*pad0;
	long	pad1;
	long	pad2;
	long	pad3;
	u_long	pad4;
	u_long	pad5;
	u_long	pad6;

	int	bsdi_ostype;		/* "BSD/386" on BSD/386 */
	int	bsdi_osrelease;		/* "1.1" on BSD/386 */
	long	pad7;
	long	pad8;
	char	*pad9;

	long	pad10;
	long	pad11;
	int	pad12;
	long	pad13;
	quad_t	pad14;
	long	pad15;

	struct	timeval pad16;
	/* we dont set this, because BSDI's uname used gethostname() instead */
	int	bsdi_hostname;		/* hostname on BSD/386 */

	/* the actual string data is appended here */

} bsdi_si;
/*
 * this data is appended to the end of the bsdi_si structure during copyout.
 * The "char *" offsets are relative to the base of the bsdi_si struct.
 * This contains "FreeBSD\02.0-BUILT-nnnnnn\0i386\0", and these strings
 * should not exceed the length of the buffer here... (or else!! :-)
 */
static char bsdi_strings[80];	/* It had better be less than this! */

#ifndef _SYS_SYSPROTO_H_
struct getkerninfo_args {
	int	op;
	char	*where;
	size_t	*size;
	int	arg;
};
#endif

int
ogetkerninfo(struct proc *p, struct getkerninfo_args *uap)
{
	int error, name[6];
	size_t size;

	switch (uap->op & 0xff00) {

	case KINFO_RT:
		name[0] = CTL_NET;
		name[1] = PF_ROUTE;
		name[2] = 0;
		name[3] = (uap->op & 0xff0000) >> 16;
		name[4] = uap->op & 0xff;
		name[5] = uap->arg;
		error = userland_sysctl(p, name, 6, uap->where, uap->size,
			0, 0, 0, &size);
		break;

	case KINFO_VNODE:
		name[0] = CTL_KERN;
		name[1] = KERN_VNODE;
		error = userland_sysctl(p, name, 2, uap->where, uap->size,
			0, 0, 0, &size);
		break;

	case KINFO_PROC:
		name[0] = CTL_KERN;
		name[1] = KERN_PROC;
		name[2] = uap->op & 0xff;
		name[3] = uap->arg;
		error = userland_sysctl(p, name, 4, uap->where, uap->size,
			0, 0, 0, &size);
		break;

	case KINFO_FILE:
		name[0] = CTL_KERN;
		name[1] = KERN_FILE;
		error = userland_sysctl(p, name, 2, uap->where, uap->size,
			0, 0, 0, &size);
		break;

	case KINFO_METER:
		name[0] = CTL_VM;
		name[1] = VM_METER;
		error = userland_sysctl(p, name, 2, uap->where, uap->size,
			0, 0, 0, &size);
		break;

	case KINFO_LOADAVG:
		name[0] = CTL_VM;
		name[1] = VM_LOADAVG;
		error = userland_sysctl(p, name, 2, uap->where, uap->size,
			0, 0, 0, &size);
		break;

	case KINFO_CLOCKRATE:
		name[0] = CTL_KERN;
		name[1] = KERN_CLOCKRATE;
		error = userland_sysctl(p, name, 2, uap->where, uap->size,
			0, 0, 0, &size);
		break;

	case KINFO_BSDI_SYSINFO: {
		/*
		 * this is pretty crude, but it's just enough for uname()
		 * from BSDI's 1.x libc to work.
		 *
		 * In particular, it doesn't return the same results when
		 * the supplied buffer is too small.  BSDI's version apparently
		 * will return the amount copied, and set the *size to how
		 * much was needed.  The emulation framework here isn't capable
		 * of that, so we just set both to the amount copied.
		 * BSDI's 2.x product apparently fails with ENOMEM in this
		 * scenario.
		 */

		u_int needed;
		u_int left;
		char *s;

		bzero((char *)&bsdi_si, sizeof(bsdi_si));
		bzero(bsdi_strings, sizeof(bsdi_strings));

		s = bsdi_strings;

		bsdi_si.bsdi_ostype = (s - bsdi_strings) + sizeof(bsdi_si);
		strcpy(s, ostype);
		s += strlen(s) + 1;

		bsdi_si.bsdi_osrelease = (s - bsdi_strings) + sizeof(bsdi_si);
		strcpy(s, osrelease);
		s += strlen(s) + 1;

		bsdi_si.bsdi_machine = (s - bsdi_strings) + sizeof(bsdi_si);
		strcpy(s, machine);
		s += strlen(s) + 1;

		needed = sizeof(bsdi_si) + (s - bsdi_strings);

		if (uap->where == NULL) {
			/* process is asking how much buffer to supply.. */
			size = needed;
			error = 0;
			break;
		}


		/* if too much buffer supplied, trim it down */
		if (size > needed)
			size = needed;

		/* how much of the buffer is remaining */
		left = size;

		if ((error = copyout((char *)&bsdi_si, uap->where, left)) != 0)
			break;

		/* is there any point in continuing? */
		if (left > sizeof(bsdi_si)) {
			left -= sizeof(bsdi_si);
			error = copyout(&bsdi_strings,
					uap->where + sizeof(bsdi_si), left);
		}
		break;
	}

	default:
		return (EOPNOTSUPP);
	}
	if (error)
		return (error);
	p->p_retval[0] = size;
	if (uap->size)
		error = copyout((caddr_t)&size, (caddr_t)uap->size,
		    sizeof(size));
	return (error);
}
#endif /* COMPAT_43 */

#endif
