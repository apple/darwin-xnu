/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
#include <sys/proc_internal.h>
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
lck_rw_t * sysctl_geometry_lock = NULL;

static void
sysctl_sysctl_debug_dump_node(struct sysctl_oid_list *l, int i);



/*
 * Locking and stats
 */
static struct sysctl_lock memlock;

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

	if(sysctl_geometry_lock == NULL)
	{
		/* Initialise the geometry lock for reading/modifying the sysctl tree
		 * This is done here because IOKit registers some sysctls before bsd_init()
		 * calls sysctl_register_fixed().
		 */

		lck_grp_t* lck_grp  = lck_grp_alloc_init("sysctl", NULL);
		sysctl_geometry_lock = lck_rw_alloc_init(lck_grp, NULL);
	}
	/* Get the write lock to modify the geometry */
	lck_rw_lock_exclusive(sysctl_geometry_lock);

	/*
	 * If this oid has a number OID_AUTO, give it a number which
	 * is greater than any current oid.  Make sure it is at least
	 * OID_AUTO_START to leave space for pre-assigned oid numbers.
	 */
	if (oidp->oid_number == OID_AUTO) {
		/* First, find the highest oid in the parent list >OID_AUTO_START-1 */
		n = OID_AUTO_START;
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

	/* Release the write lock */
	lck_rw_unlock_exclusive(sysctl_geometry_lock);

	splx_kernel_funnel(fnl);
}

void sysctl_unregister_oid(struct sysctl_oid *oidp)
{
	funnel_t *fnl;

	fnl = spl_kernel_funnel();

	/* Get the write lock to modify the geometry */
	lck_rw_lock_exclusive(sysctl_geometry_lock);

	SLIST_REMOVE(oidp->oid_parent, oidp, sysctl_oid, oid_link);

	/* Release the write lock */
	lck_rw_unlock_exclusive(sysctl_geometry_lock);

	splx_kernel_funnel(fnl);
}

/*
 * Bulk-register all the oids in a linker_set.
 */
void sysctl_register_set(const char *set)
{
	struct sysctl_oid **oidpp, *oidp;

	LINKER_SET_FOREACH(oidpp, set) {
		oidp = *oidpp;
		if (!(oidp->oid_kind & CTLFLAG_NOAUTO)) {
		    sysctl_register_oid(oidp);
		}
	}
}

void sysctl_unregister_set(const char *set)
{
	struct sysctl_oid **oidpp, *oidp;

	LINKER_SET_FOREACH(oidpp, set) {
		oidp = *oidpp;
		if (!(oidp->oid_kind & CTLFLAG_NOAUTO)) {
		    sysctl_unregister_oid(oidp);
		}
	}
}


/*
 * Register the kernel's oids on startup.
 */

void
sysctl_register_all()
{
	sysctl_register_set("__sysctl_set");
}

void
sysctl_register_fixed(void)
{
	sysctl_register_all();
}

/*
 * New handler interface
 *   If the sysctl caller (user mode or kernel mode) is interested in the
 *   value (req->oldptr != NULL), we copy the data (bigValue etc.) out,
 *   if the caller wants to set the value (req->newptr), we copy
 *   the data in (*pValue etc.).
 */

int
sysctl_io_number(struct sysctl_req *req, long long bigValue, size_t valueSize, void *pValue, int *changed) {
	int		smallValue;
	int		error;

	if (changed) *changed = 0;

	/*
	 * Handle the various combinations of caller buffer size and
	 * data value size.  We are generous in the case where the
	 * caller has specified a 32-bit buffer but the value is 64-bit
	 * sized.
	 */

	/* 32 bit value expected or 32 bit buffer offered */
	if ((valueSize == sizeof(int)) ||
	    ((req->oldlen == sizeof(int)) && (valueSize == sizeof(long long)))) {
		smallValue = (int)bigValue;
		if ((long long)smallValue != bigValue)
			return(ERANGE);
		error = SYSCTL_OUT(req, &smallValue, sizeof(smallValue));
	} else {
		/* any other case is either size-equal or a bug */
		error = SYSCTL_OUT(req, &bigValue, valueSize);
	}
	/* error or nothing to set */
	if (error || !req->newptr)
		return(error);

	/* set request for constant */
	if (pValue == NULL)
		return(EPERM);

	/* set request needs to convert? */
	if ((req->newlen == sizeof(int)) && (valueSize == sizeof(long long))) {
		/* new value is 32 bits, upconvert to 64 bits */
		error = SYSCTL_IN(req, &smallValue, sizeof(smallValue));
		if (!error)
			*(long long *)pValue = (long long)smallValue;
	} else if ((req->newlen == sizeof(long long)) && (valueSize == sizeof(int))) {
		/* new value is 64 bits, downconvert to 32 bits and range check */
		error = SYSCTL_IN(req, &bigValue, sizeof(bigValue));
		if (!error) {
			smallValue = (int)bigValue;
			if ((long long)smallValue != bigValue)
				return(ERANGE);
			*(int *)pValue = smallValue;
		}
	} else {
		/* sizes match, just copy in */
		error = SYSCTL_IN(req, pValue, valueSize);
	}
	if (!error && changed)
		*changed = 1;
	return(error);
}

int
sysctl_io_string(struct sysctl_req *req, char *pValue, size_t valueSize, int trunc, int *changed)
{
	int error;

	if (changed) *changed = 0;

	if (trunc && req->oldptr && req->oldlen && (req->oldlen<strlen(pValue) + 1)) {
		/* If trunc != 0, if you give it a too small (but larger than
		 * 0 bytes) buffer, instead of returning ENOMEM, it truncates the
		 * returned string to the buffer size.  This preserves the semantics
		 * of some library routines implemented via sysctl, which truncate
		 * their returned data, rather than simply returning an error. The
		 * returned string is always NUL terminated. */
		error = SYSCTL_OUT(req, pValue, req->oldlen-1);
		if (!error) {
			char c = 0;
			error = SYSCTL_OUT(req, &c, 1);
		}
	} else {
		/* Copy string out */
		error = SYSCTL_OUT(req, pValue, strlen(pValue) + 1);
	}

	/* error or no new value */
	if (error || !req->newptr)
		return(error);

	/* attempt to set read-only value */
	if (valueSize == 0)
		return(EPERM);

	/* make sure there's room for the new string */
	if (req->newlen >= valueSize)
		return(EINVAL);

	/* copy the string in and force NUL termination */
	error = SYSCTL_IN(req, pValue, req->newlen);
	pValue[req->newlen] = '\0';

	if (!error && changed)
		*changed = 1;
	return(error);
}

int sysctl_io_opaque(struct sysctl_req *req,void *pValue, size_t valueSize, int *changed)
{
	int error;

	if (changed) *changed = 0;

	/* Copy blob out */
	error = SYSCTL_OUT(req, pValue, valueSize);

	/* error or nothing to set */
	if (error || !req->newptr)
		return(error);

	error = SYSCTL_IN(req, pValue, valueSize);

	if (!error && changed)
		*changed = 1;
	return(error);
}

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
sysctl_sysctl_debug(__unused struct sysctl_oid *oidp, __unused void *arg1,
	__unused int arg2, __unused struct sysctl_req *req)
{
	sysctl_sysctl_debug_dump_node(&sysctl__children, 0);
	return ENOENT;
}

SYSCTL_PROC(_sysctl, 0, debug, CTLTYPE_STRING|CTLFLAG_RD,
	0, 0, sysctl_sysctl_debug, "-", "");

static int
sysctl_sysctl_name(__unused struct sysctl_oid *oidp, void *arg1, int arg2,
        struct sysctl_req *req)
{
	int *name = (int *) arg1;
	u_int namelen = arg2;
	int error = 0;
	struct sysctl_oid *oid;
	struct sysctl_oid_list *lsp = &sysctl__children, *lsp2;
	char tempbuf[10];

	while (namelen) {
		if (!lsp) {
			snprintf(tempbuf,sizeof(tempbuf),"%d",*name);
			if (req->oldidx)
				error = SYSCTL_OUT(req, ".", 1);
			if (!error)
				error = SYSCTL_OUT(req, tempbuf, strlen(tempbuf));
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

			if (!SLIST_FIRST(lsp))
				/* This node had no children - skip it! */
				continue;

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
sysctl_sysctl_next(__unused struct sysctl_oid *oidp, void *arg1, int arg2,
        struct sysctl_req *req)
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
sysctl_sysctl_name2oid(__unused struct sysctl_oid *oidp, __unused void *arg1,
	__unused int arg2, struct sysctl_req *req)
{
	char *p;
	int error, oid[CTL_MAXNAME];
	int len = 0;		/* set by name2oid() */
	struct sysctl_oid *op = 0;

	if (!req->newlen) 
		return ENOENT;
	if (req->newlen >= MAXPATHLEN)	/* XXX arbitrary, undocumented */
		return (ENAMETOOLONG);

	MALLOC(p, char *,req->newlen+1, M_TEMP, M_WAITOK);
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
sysctl_sysctl_oidfmt(__unused struct sysctl_oid *oidp, void *arg1, int arg2,
        struct sysctl_req *req)
{
	int *name = (int *) arg1, error;
	u_int namelen = arg2;
	u_int indx;
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
sysctl_handle_int(__unused struct sysctl_oid *oidp, void *arg1, int arg2,
        struct sysctl_req *req)
{
	return sysctl_io_number(req, arg1? *(int*)arg1: arg2, sizeof(int), arg1, NULL);
}

/*
 * Handle a long, signed or unsigned.  arg1 points to it.
 */

int
sysctl_handle_long(__unused struct sysctl_oid *oidp, void *arg1,
	__unused int arg2, struct sysctl_req *req)
{
	if (!arg1)
		return (EINVAL);
	return sysctl_io_number(req, *(long*)arg1, sizeof(long), arg1, NULL);
}

/*
 * Handle a quad, signed or unsigned.  arg1 points to it.
 */

int
sysctl_handle_quad(__unused struct sysctl_oid *oidp, void *arg1,
	__unused int arg2, struct sysctl_req *req)
{
	if (!arg1)
		return (EINVAL);
	return sysctl_io_number(req, *(long long*)arg1, sizeof(long long), arg1, NULL);
}

/*
 * Expose an int value as a quad.
 *
 * This interface allows us to support interfaces defined
 * as using quad values while the implementation is still
 * using ints.
 */
int
sysctl_handle_int2quad(__unused struct sysctl_oid *oidp, void *arg1,
	__unused int arg2, struct sysctl_req *req)
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
sysctl_handle_string( __unused struct sysctl_oid *oidp, void *arg1, int arg2,
        struct sysctl_req *req)
{
	return sysctl_io_string(req, arg1, arg2, 0, NULL);
}

/*
 * Handle any kind of opaque data.
 * arg1 points to it, arg2 is the size.
 */

int
sysctl_handle_opaque(__unused struct sysctl_oid *oidp, void *arg1, int arg2,
        struct sysctl_req *req)
{
	return sysctl_io_opaque(req, arg1, arg2, NULL);
}

/*
 * Transfer functions to/from kernel space.
 */
static int
sysctl_old_kernel(struct sysctl_req *req, const void *p, size_t l)
{
	size_t i = 0;

	if (req->oldptr) {
		i = l;
		if (i > req->oldlen - req->oldidx)
			i = req->oldlen - req->oldidx;
		if (i > 0)
			bcopy((const void*)p, CAST_DOWN(char *, (req->oldptr + req->oldidx)), i);
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
	bcopy(CAST_DOWN(char *, (req->newptr + req->newidx)), p, l);
	req->newidx += l;
	return (0);
}

int
kernel_sysctl(struct proc *p, int *name, u_int namelen, void *old, size_t *oldlenp, void *new, size_t newlen)
{
	int error = 0;
	struct sysctl_req req;

	/*
	 * Construct request.
	 */
	bzero(&req, sizeof req);
	req.p = p;
	if (oldlenp)
		req.oldlen = *oldlenp;
	if (old)
		req.oldptr = CAST_USER_ADDR_T(old);
	if (newlen) {
		req.newlen = newlen;
		req.newptr = CAST_USER_ADDR_T(new);
	}
	req.oldfunc = sysctl_old_kernel;
	req.newfunc = sysctl_new_kernel;
	req.lock = 1;

	/* make the request */
	error = sysctl_root(0, name, namelen, &req);

	/* unlock memory if required */
	if (req.lock == 2)
		vsunlock(req.oldptr, (user_size_t)req.oldlen, B_WRITE);

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
			error = copyout((const void*)p, (req->oldptr + req->oldidx), i);
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
	error = copyin((req->newptr + req->newidx), p, l);
	req->newidx += l;
	return (error);
}

/*
 * Traverse our tree, and find the right node, execute whatever it points
 * at, and return the resulting error code.
 */

int
sysctl_root(__unused struct sysctl_oid *oidp, void *arg1, int arg2,
        struct sysctl_req *req)
{
	int *name = (int *) arg1;
	u_int namelen = arg2;
	u_int indx;
	int i;
	struct sysctl_oid *oid;
	struct sysctl_oid_list *lsp = &sysctl__children;
	int error;
	funnel_t *fnl = NULL;
	boolean_t funnel_held = FALSE;

	/* Get the read lock on the geometry */
	lck_rw_lock_shared(sysctl_geometry_lock);

	oid = SLIST_FIRST(lsp);

	indx = 0;
	while (oid && indx < CTL_MAXNAME) {
		if (oid->oid_number == name[indx]) {
			indx++;
			if (!(oid->oid_kind & CTLFLAG_LOCKED))
			{
				funnel_held = TRUE;
			}
			if (oid->oid_kind & CTLFLAG_NOLOCK)
				req->lock = 0;
			if ((oid->oid_kind & CTLTYPE) == CTLTYPE_NODE) {
				if (oid->oid_handler)
					goto found;
				if (indx == namelen)
				{
					error = ENOENT;
					goto err;
				}

				lsp = (struct sysctl_oid_list *)oid->oid_arg1;
				oid = SLIST_FIRST(lsp);
			} else {
				if (indx != namelen)
				{
					error = EISDIR;
					goto err;
				}
				goto found;
			}
		} else {
			oid = SLIST_NEXT(oid, oid_link);
		}
	}
	error = ENOENT;
	goto err;
found:
	/* If writing isn't allowed */
	if (req->newptr && (!(oid->oid_kind & CTLFLAG_WR) ||
			    ((oid->oid_kind & CTLFLAG_SECURE) && securelevel > 0))) {
		error = (EPERM);
		goto err;
	}

	/*
	 * If we're inside the kernel, the OID must be marked as kernel-valid.
	 * XXX This mechanism for testing is bad.
	 */
	if ((req->oldfunc == sysctl_old_kernel) && !(oid->oid_kind & CTLFLAG_KERN))
	{
		error = (EPERM);
		goto err;
	}

	/* Most likely only root can write */
	if (!(oid->oid_kind & CTLFLAG_ANYBODY) &&
	    req->newptr && req->p &&
	    (error = proc_suser(req->p)))
		goto err;

	if (!oid->oid_handler) {
	    error = EINVAL;
		goto err;
	}

	if (funnel_held)
	{
		fnl = spl_kernel_funnel();
		MEMLOCK_LOCK();
	}

	if ((oid->oid_kind & CTLTYPE) == CTLTYPE_NODE) {
		i = (oid->oid_handler) (oid,
					name + indx, namelen - indx,
					req);
	} else {
		i = (oid->oid_handler) (oid,
					oid->oid_arg1, oid->oid_arg2,
					req);
	}
	error = i;

	if (funnel_held)
	{
		MEMLOCK_UNLOCK();
		splx_kernel_funnel(fnl);
	}

err:
	lck_rw_done(sysctl_geometry_lock);
	return (error);
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

 	error = copyin(CAST_USER_ADDR_T(uap->name), &name, uap->namelen * sizeof(int));
 	if (error)
		return (error);

	error = userland_sysctl(p, name, uap->namelen,
		                    CAST_USER_ADDR_T(uap->old), uap->oldlenp, 0,
		                    CAST_USER_ADDR_T(uap->new), uap->newlen, &j);
	if (error && error != ENOMEM)
		return (error);
	if (uap->oldlenp) {
		i = copyout(&j, CAST_USER_ADDR_T(uap->oldlenp), sizeof(j));
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
userland_sysctl(struct proc *p, int *name, u_int namelen, user_addr_t oldp, 
                size_t *oldlenp, int inkernel, user_addr_t newp, size_t newlen, 
                size_t *retval)
{
	int error = 0;
	struct sysctl_req req, req2;

	bzero(&req, sizeof req);

	req.p = p;

	if (oldlenp) {
		if (inkernel) {
			req.oldlen = *oldlenp;
		} else {
			error = copyin(CAST_USER_ADDR_T(oldlenp), &req.oldlen, sizeof(*oldlenp));
			if (error)
				return (error);
		}
	}

	if (oldp) {
		req.oldptr = oldp;
	}

	if (newlen) {
		req.newlen = newlen;
		req.newptr = newp;
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

