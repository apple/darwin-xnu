/*
 * Copyright (c) 2000-2013 Apple Inc. All rights reserved.
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
 *
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
#include <sys/kauth.h>
#include <sys/systm.h>
#include <sys/sysproto.h>

#include <security/audit/audit.h>
#include <pexpert/pexpert.h>

#if CONFIG_MACF
#include <security/mac_framework.h>
#endif

lck_grp_t * sysctl_lock_group = NULL;
lck_rw_t * sysctl_geometry_lock = NULL;
lck_mtx_t * sysctl_unlocked_node_lock = NULL;

/*
 * Conditionally allow dtrace to see these functions for debugging purposes.
 */
#ifdef STATIC
#undef STATIC
#endif
#if 0
#define	STATIC
#else
#define STATIC static
#endif

/* forward declarations  of static functions */
STATIC void sysctl_sysctl_debug_dump_node(struct sysctl_oid_list *l, int i);
STATIC int sysctl_sysctl_debug(struct sysctl_oid *oidp, void *arg1,
	int arg2, struct sysctl_req *req);
STATIC int sysctl_sysctl_name(struct sysctl_oid *oidp, void *arg1,
	int arg2, struct sysctl_req *req);
STATIC int sysctl_sysctl_next_ls (struct sysctl_oid_list *lsp,
	int *name, u_int namelen, int *next, int *len, int level,
	struct sysctl_oid **oidpp);
STATIC int sysctl_old_kernel(struct sysctl_req *req, const void *p, size_t l);
STATIC int sysctl_new_kernel(struct sysctl_req *req, void *p, size_t l);
STATIC int name2oid (char *name, int *oid, u_int *len);
STATIC int sysctl_sysctl_name2oid(struct sysctl_oid *oidp, void *arg1, int arg2, struct sysctl_req *req);
STATIC int sysctl_sysctl_next(struct sysctl_oid *oidp, void *arg1, int arg2,
        struct sysctl_req *req);
STATIC int sysctl_sysctl_oidfmt(struct sysctl_oid *oidp, void *arg1, int arg2, struct sysctl_req *req);
STATIC int sysctl_old_user(struct sysctl_req *req, const void *p, size_t l);
STATIC int sysctl_new_user(struct sysctl_req *req, void *p, size_t l);

STATIC void sysctl_create_user_req(struct sysctl_req *req, struct proc *p, user_addr_t oldp,
								   size_t oldlen, user_addr_t newp, size_t newlen);
STATIC int sysctl_root(boolean_t from_kernel, boolean_t string_is_canonical, char *namestring, size_t namestringlen, int *name, u_int namelen, struct sysctl_req *req);

int	kernel_sysctl(struct proc *p, int *name, u_int namelen, void *old, size_t *oldlenp, void *new, size_t newlen);
int	kernel_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
int	userland_sysctl(boolean_t string_is_canonical,
					char *namestring, size_t namestringlen,
					int *name, u_int namelen, struct sysctl_req *req,
					size_t *retval);

struct sysctl_oid_list sysctl__children; /* root list */

/*
 * Initialization of the MIB tree.
 *
 * Order by number in each list.
 */

void
sysctl_register_oid(struct sysctl_oid *new_oidp)
{
	struct sysctl_oid *oidp = NULL;
	struct sysctl_oid_list *parent = new_oidp->oid_parent;
	struct sysctl_oid *p;
	struct sysctl_oid *q;
	int n;

	/*
	 * The OID can be old-style (needs copy), new style without an earlier
	 * version (also needs copy), or new style with a matching version (no
	 * copy needed).  Later versions are rejected (presumably, the OID
	 * structure was changed for a necessary reason).
	 */
	if (!(new_oidp->oid_kind & CTLFLAG_OID2)) {
		/*
		 * XXX:	M_TEMP is perhaps not the most apropriate zone, as it
		 * XXX:	will subject us to use-after-free by other consumers.
		 */
		MALLOC(oidp, struct sysctl_oid *, sizeof(*oidp), M_TEMP, M_WAITOK | M_ZERO);
		if (oidp == NULL)
			return;		/* reject: no memory */

		/*
		 * Copy the structure only through the oid_fmt field, which
		 * is the last field in a non-OID2 OID structure.
		 *
		 * Note:	We may want to set the oid_descr to the
		 *		oid_name (or "") at some future date.
		 */
		memcpy(oidp, new_oidp, offsetof(struct sysctl_oid, oid_descr));
	} else {
		/* It's a later version; handle the versions we know about */
		switch (new_oidp->oid_version) {
		case SYSCTL_OID_VERSION:
			/* current version */
			oidp = new_oidp;
			break;
		default:
			return;			/* rejects unknown version */
		}
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
		/*
		 * Reflect the number in an llocated OID into the template
		 * of the caller for sysctl_unregister_oid() compares.
		 */
		if (oidp != new_oidp)
			new_oidp->oid_number = oidp->oid_number;
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
}

void
sysctl_unregister_oid(struct sysctl_oid *oidp)
{
	struct sysctl_oid *removed_oidp = NULL;	/* OID removed from tree */
	struct sysctl_oid *old_oidp = NULL;	/* OID compatibility copy */

	/* Get the write lock to modify the geometry */
	lck_rw_lock_exclusive(sysctl_geometry_lock);

	if (!(oidp->oid_kind & CTLFLAG_OID2)) {
		/*
		 * We're using a copy so we can get the new fields in an
		 * old structure, so we have to iterate to compare the
		 * partial structure; when we find a match, we remove it
		 * normally and free the memory.
		 */
		SLIST_FOREACH(old_oidp, oidp->oid_parent, oid_link) {
			if (!memcmp(&oidp->oid_number, &old_oidp->oid_number, (offsetof(struct sysctl_oid, oid_descr)-offsetof(struct sysctl_oid, oid_number)))) {
                break;
            }
		}
		if (old_oidp != NULL) {
			SLIST_REMOVE(old_oidp->oid_parent, old_oidp, sysctl_oid, oid_link);
			removed_oidp = old_oidp;
		}
	} else {
		/* It's a later version; handle the versions we know about */
		switch (oidp->oid_version) {
		case SYSCTL_OID_VERSION:
			/* We can just remove the OID directly... */
			SLIST_REMOVE(oidp->oid_parent, oidp, sysctl_oid, oid_link);
			removed_oidp = oidp;
			break;
		default:
			 /* XXX: Can't happen; probably tree coruption.*/
			break;			/* rejects unknown version */
		}
	}

	/*
	 * We've removed it from the list at this point, but we don't want
	 * to return to the caller until all handler references have drained
	 * out.  Doing things in this order prevent other people coming in
	 * and starting new operations against the OID node we want removed.
	 *
	 * Note:	oidp could be NULL if it wasn't found.
	 */
	while(removed_oidp && removed_oidp->oid_refcnt) {
		lck_rw_sleep(sysctl_geometry_lock, LCK_SLEEP_EXCLUSIVE, &removed_oidp->oid_refcnt, THREAD_UNINT);
	}

	/* Release the write lock */
	lck_rw_unlock_exclusive(sysctl_geometry_lock);

	/* If it was allocated, free it after dropping the lock */
	if (old_oidp != NULL) {
		FREE(old_oidp, M_TEMP);
	}
}

/*
 * Bulk-register all the oids in a linker_set.
 */
void
sysctl_register_set(const char *set)
{
	struct sysctl_oid **oidpp, *oidp;

	LINKER_SET_FOREACH(oidpp, struct sysctl_oid **, set) {
		oidp = *oidpp;
		if (!(oidp->oid_kind & CTLFLAG_NOAUTO)) {
		    sysctl_register_oid(oidp);
		}
	}
}

void
sysctl_unregister_set(const char *set)
{
	struct sysctl_oid **oidpp, *oidp;

	LINKER_SET_FOREACH(oidpp, struct sysctl_oid **, set) {
		oidp = *oidpp;
		if (!(oidp->oid_kind & CTLFLAG_NOAUTO)) {
		    sysctl_unregister_oid(oidp);
		}
	}
}

/*
 * Exported in BSDKernel.exports, kept for binary compatibility
 */
#if defined(__x86_64__)
void
sysctl_register_fixed(void)
{
}
#endif

/*
 * Register the kernel's oids on startup.
 */

void
sysctl_early_init(void)
{
	/*
	 * Initialize the geometry lock for reading/modifying the
	 * sysctl tree. This is done here because IOKit registers
	 * some sysctl's before bsd_init() would otherwise perform
	 * subsystem initialization.
	 */

	sysctl_lock_group  = lck_grp_alloc_init("sysctl", NULL);
	sysctl_geometry_lock = lck_rw_alloc_init(sysctl_lock_group, NULL);
	sysctl_unlocked_node_lock = lck_mtx_alloc_init(sysctl_lock_group, NULL);

	sysctl_register_set("__sysctl_set");
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
	if (((valueSize == sizeof(int)) ||
	    ((req->oldlen == sizeof(int)) && (valueSize == sizeof(long long))))
			&& (req->oldptr)) {
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

/*
 * sysctl_sysctl_debug_dump_node
 *
 * Description:	Dump debug information for a given sysctl_oid_list at the
 *		given oid depth out to the kernel log, via printf
 *
 * Parameters:	l				sysctl_oid_list pointer
 *		i				current node depth
 *
 * Returns:	(void)
 *
 * Implicit:	kernel log, modified
 *
 * Locks:	Assumes sysctl_geometry_lock is held prior to calling
 *
 * Notes:	This function may call itself recursively to resolve Node
 *		values, which potentially have an inferioer sysctl_oid_list
 *
 *		This function is only callable indirectly via the function
 *		sysctl_sysctl_debug()
 *
 * Bugs:	The node depth indentation does not work; this may be an
 *		artifact of leading space removal by the log daemon itself
 *		or some intermediate routine.
 */
STATIC void
sysctl_sysctl_debug_dump_node(struct sysctl_oid_list *l, int i)
{
	int k;
	struct sysctl_oid *oidp;

	SLIST_FOREACH(oidp, l, oid_link) {

		for (k=0; k<i; k++)
			printf(" ");

		printf("%d %s ", oidp->oid_number, oidp->oid_name);

		printf("%c%c%c",
			oidp->oid_kind & CTLFLAG_LOCKED ? 'L':' ',
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

/*
 * sysctl_sysctl_debug
 *
 * Description:	This function implements the "sysctl.debug" portion of the
 *		OID space for sysctl.
 *
 * OID:		0, 0
 *
 * Parameters:	__unused
 *
 * Returns:	ENOENT
 *
 * Implicit:	kernel log, modified
 *
 * Locks:	Acquires and then releases a read lock on the
 *		sysctl_geometry_lock
 */
STATIC int
sysctl_sysctl_debug(__unused struct sysctl_oid *oidp, __unused void *arg1,
	__unused int arg2, __unused struct sysctl_req *req)
{
	lck_rw_lock_shared(sysctl_geometry_lock);
	sysctl_sysctl_debug_dump_node(&sysctl__children, 0);
	lck_rw_done(sysctl_geometry_lock);
	return ENOENT;
}

SYSCTL_PROC(_sysctl, 0, debug, CTLTYPE_STRING|CTLFLAG_RD | CTLFLAG_LOCKED,
	0, 0, sysctl_sysctl_debug, "-", "");

/*
 * sysctl_sysctl_name
 *
 * Description:	Convert an OID into a string name; this is used by the user
 *		space sysctl() command line utility; this is done in a purely
 *		advisory capacity (e.g. to provide node names for "sysctl -A"
 *		output).
 *
 * OID:		0, 1
 *
 * Parameters:	oidp				__unused
 *		arg1				A pointer to the OID name list
 *						integer array, beginning at
 *						adjusted option base 2
 *		arg2				The number of elements which
 *						remain in the name array
 *
 * Returns:	0				Success
 *	SYSCTL_OUT:EPERM			Permission denied
 *	SYSCTL_OUT:EFAULT			Bad user supplied buffer
 *	SYSCTL_OUT:???				Return value from user function
 *						for SYSCTL_PROC leaf node
 *
 * Implict:	Contents of user request buffer, modified
 *
 * Locks:	Acquires and then releases a read lock on the
 *		sysctl_geometry_lock
 *
 * Notes:	SPI (System Programming Interface); this is subject to change
 *		and may not be relied upon by third party applications; use
 *		a subprocess to communicate with the "sysctl" command line
 *		command instead, if you believe you need this functionality.
 *		Preferrably, use sysctlbyname() instead.
 *
 *		Setting of the NULL termination of the output string is
 *		delayed until after the geometry lock is dropped.  If there
 *		are no Entries remaining in the OID name list when this
 *		function is called, it will still write out the termination
 *		byte.
 *
 *		This function differs from other sysctl functions in that
 *		it can not take an output buffer length of 0 to determine the
 *		space which will be required.  It is suggested that the buffer
 *		length be PATH_MAX, and that authors of new sysctl's refrain
 *		from exceeding this string length.
 */
STATIC int
sysctl_sysctl_name(__unused struct sysctl_oid *oidp, void *arg1, int arg2,
        struct sysctl_req *req)
{
	int *name = (int *) arg1;
	u_int namelen = arg2;
	int error = 0;
	struct sysctl_oid *oid;
	struct sysctl_oid_list *lsp = &sysctl__children, *lsp2;
	char tempbuf[10];

	lck_rw_lock_shared(sysctl_geometry_lock);
	while (namelen) {
		if (!lsp) {
			snprintf(tempbuf,sizeof(tempbuf),"%d",*name);
			if (req->oldidx)
				error = SYSCTL_OUT(req, ".", 1);
			if (!error)
				error = SYSCTL_OUT(req, tempbuf, strlen(tempbuf));
			if (error) {
				lck_rw_done(sysctl_geometry_lock);
				return (error);
			}
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
			if (error) {
				lck_rw_done(sysctl_geometry_lock);
				return (error);
			}

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
	lck_rw_done(sysctl_geometry_lock);
	return (SYSCTL_OUT(req, "", 1));
}

SYSCTL_NODE(_sysctl, 1, name, CTLFLAG_RD | CTLFLAG_LOCKED, sysctl_sysctl_name, "");

/*
 * sysctl_sysctl_next_ls
 *
 * Description:	For a given OID name value, return the next consecutive OID
 *		name value within the geometry tree
 *
 * Parameters:	lsp				The OID list to look in
 *		name				The OID name to start from
 *		namelen				The length of the OID name
 *		next				Pointer to new oid storage to
 *						fill in
 *		len				Pointer to receive new OID
 *						length value of storage written
 *		level				OID tree depth (used to compute
 *						len value)
 *		oidpp				Pointer to OID list entry
 *						pointer; used to walk the list
 *						forward across recursion
 *
 * Returns:	0				Returning a new entry
 *		1				End of geometry list reached
 *
 * Implicit:	*next				Modified to contain the new OID
 *		*len				Modified to contain new length
 *
 * Locks:	Assumes sysctl_geometry_lock is held prior to calling
 *
 * Notes:	This function will not return OID values that have special
 *		handlers, since we can not tell wheter these handlers consume
 *		elements from the OID space as parameters.  For this reason,
 *		we STRONGLY discourage these types of handlers
 */
STATIC int
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

/*
 * sysctl_sysctl_next
 *
 * Description:	This is an iterator function designed to iterate the oid tree
 *		and provide a list of OIDs for use by the user space "sysctl"
 *		command line tool
 *
 * OID:		0, 2
 *
 * Parameters:	oidp				__unused
 *		arg1				Pointer to start OID name
 *		arg2				Start OID name length
 *		req				Pointer to user request buffer
 *
 * Returns:	0				Success
 *		ENOENT				Reached end of OID space
 *	SYSCTL_OUT:EPERM			Permission denied
 *	SYSCTL_OUT:EFAULT			Bad user supplied buffer
 *	SYSCTL_OUT:???				Return value from user function
 *						for SYSCTL_PROC leaf node
 *
 * Implict:	Contents of user request buffer, modified
 *
 * Locks:	Acquires and then releases a read lock on the
 *		sysctl_geometry_lock
 *
 * Notes:	SPI (System Programming Interface); this is subject to change
 *		and may not be relied upon by third party applications; use
 *		a subprocess to communicate with the "sysctl" command line
 *		command instead, if you believe you need this functionality.
 *		Preferrably, use sysctlbyname() instead.
 *
 *		This function differs from other sysctl functions in that
 *		it can not take an output buffer length of 0 to determine the
 *		space which will be required.  It is suggested that the buffer
 *		length be PATH_MAX, and that authors of new sysctl's refrain
 *		from exceeding this string length.
 */
STATIC int
sysctl_sysctl_next(__unused struct sysctl_oid *oidp, void *arg1, int arg2,
        struct sysctl_req *req)
{
	int *name = (int *) arg1;
	u_int namelen = arg2;
	int i, j, error;
	struct sysctl_oid *oid;
	struct sysctl_oid_list *lsp = &sysctl__children;
	int newoid[CTL_MAXNAME];

	lck_rw_lock_shared(sysctl_geometry_lock);
	i = sysctl_sysctl_next_ls (lsp, name, namelen, newoid, &j, 1, &oid);
	lck_rw_done(sysctl_geometry_lock);
	if (i)
		return ENOENT;
	error = SYSCTL_OUT(req, newoid, j * sizeof (int));
	return (error);
}

SYSCTL_NODE(_sysctl, 2, next, CTLFLAG_RD | CTLFLAG_LOCKED, sysctl_sysctl_next, "");

/*
 * name2oid
 *
 * Description:	Support function for use by sysctl_sysctl_name2oid(); looks
 *		up an OID name given a string name.
 *
 * Parameters:	name				NULL terminated string name
 *		oid				Pointer to receive OID name
 *		len				Pointer to receive OID length
 *						pointer value (see "Notes")
 *
 * Returns:	0				Success
 *		ENOENT				Entry not found
 *
 * Implicit:	*oid				Modified to contain OID value
 *		*len				Modified to contain OID length
 *
 * Locks:	Assumes sysctl_geometry_lock is held prior to calling
 */
STATIC int
name2oid (char *name, int *oid, u_int *len)
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
			return (0);
		}

		if ((oidp->oid_kind & CTLTYPE) != CTLTYPE_NODE)
			break;

		if (oidp->oid_handler)
			break;

		lsp = (struct sysctl_oid_list *)oidp->oid_arg1;
		oidp = SLIST_FIRST(lsp);
		*p = i; /* restore */
		name = p+1;
		for (p = name; *p && *p != '.'; p++) 
				;
		i = *p;
		if (i == '.')
			*p = '\0';
	}
	return ENOENT;
}

/*
 * sysctl_sysctl_name2oid
 *
 * Description:	Translate a string name to an OID name value; this is used by
 *		the sysctlbyname() function as well as by the "sysctl" command
 *		line command.
 *
 * OID:		0, 3
 *
 * Parameters:	oidp				__unused
 *		arg1				__unused
 *		arg2				__unused
 *		req				Request structure
 *
 * Returns:	ENOENT				Input length too short
 *		ENAMETOOLONG			Input length too long
 *		ENOMEM				Could not allocate work area
 *	SYSCTL_IN/OUT:EPERM			Permission denied
 *	SYSCTL_IN/OUT:EFAULT			Bad user supplied buffer
 *	SYSCTL_IN/OUT:???			Return value from user function
 *	name2oid:ENOENT				Not found
 *
 * Implicit:	*req				Contents of request, modified
 *
 * Locks:	Acquires and then releases a read lock on the
 *		sysctl_geometry_lock
 *
 * Notes:	SPI (System Programming Interface); this is subject to change
 *		and may not be relied upon by third party applications; use
 *		a subprocess to communicate with the "sysctl" command line
 *		command instead, if you believe you need this functionality.
 *		Preferrably, use sysctlbyname() instead.
 *
 *		This function differs from other sysctl functions in that
 *		it can not take an output buffer length of 0 to determine the
 *		space which will be required.  It is suggested that the buffer
 *		length be PATH_MAX, and that authors of new sysctl's refrain
 *		from exceeding this string length.
 */
STATIC int
sysctl_sysctl_name2oid(__unused struct sysctl_oid *oidp, __unused void *arg1,
	__unused int arg2, struct sysctl_req *req)
{
	char *p;
	int error, oid[CTL_MAXNAME];
	u_int len = 0;		/* set by name2oid() */

	if (req->newlen < 1) 
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

	/*
	 * Note:	We acquire and release the geometry lock here to
	 *		avoid making name2oid needlessly complex.
	 */
	lck_rw_lock_shared(sysctl_geometry_lock);
	error = name2oid(p, oid, &len);
	lck_rw_done(sysctl_geometry_lock);

	FREE(p, M_TEMP);

	if (error)
		return (error);

	error = SYSCTL_OUT(req, oid, len * sizeof *oid);
	return (error);
}

SYSCTL_PROC(_sysctl, 3, name2oid, CTLFLAG_RW|CTLFLAG_ANYBODY|CTLFLAG_KERN | CTLFLAG_LOCKED, 0, 0, 
	sysctl_sysctl_name2oid, "I", "");

/*
 * sysctl_sysctl_oidfmt
 *
 * Description:	For a given OID name, determine the format of the data which
 *		is associated with it.  This is used by the "sysctl" command
 *		line command.
 *
 * OID:		0, 4
 *
 * Parameters:	oidp				__unused
 *		arg1				The OID name to look up
 *		arg2				The length of the OID name
 *		req				Pointer to user request buffer
 *
 * Returns:	0				Success
 *		EISDIR				Malformed request
 *		ENOENT				No such OID name
 *	SYSCTL_OUT:EPERM			Permission denied
 *	SYSCTL_OUT:EFAULT			Bad user supplied buffer
 *	SYSCTL_OUT:???				Return value from user function
 *
 * Implict:	Contents of user request buffer, modified
 *
 * Locks:	Acquires and then releases a read lock on the
 *		sysctl_geometry_lock
 *
 * Notes:	SPI (System Programming Interface); this is subject to change
 *		and may not be relied upon by third party applications; use
 *		a subprocess to communicate with the "sysctl" command line
 *		command instead, if you believe you need this functionality.
 *
 *		This function differs from other sysctl functions in that
 *		it can not take an output buffer length of 0 to determine the
 *		space which will be required.  It is suggested that the buffer
 *		length be PATH_MAX, and that authors of new sysctl's refrain
 *		from exceeding this string length.
 */
STATIC int
sysctl_sysctl_oidfmt(__unused struct sysctl_oid *oidp, void *arg1, int arg2,
        struct sysctl_req *req)
{
	int *name = (int *) arg1;
	int error = ENOENT;		/* default error: not found */
	u_int namelen = arg2;
	u_int indx;
	struct sysctl_oid *oid;
	struct sysctl_oid_list *lsp = &sysctl__children;

	lck_rw_lock_shared(sysctl_geometry_lock);
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
				if (indx != namelen) {
					error =  EISDIR;
					goto err;
				}
				goto found;
			}
		} else {
			oid = SLIST_NEXT(oid, oid_link);
		}
	}
	/* Not found */
	goto err;

found:
	if (!oid->oid_fmt)
		goto err;
	error = SYSCTL_OUT(req, 
		&oid->oid_kind, sizeof(oid->oid_kind));
	if (!error)
		error = SYSCTL_OUT(req, oid->oid_fmt, 
			strlen(oid->oid_fmt)+1);
err:
	lck_rw_done(sysctl_geometry_lock);
	return (error);
}

SYSCTL_NODE(_sysctl, 4, oidfmt, CTLFLAG_RD | CTLFLAG_LOCKED, sysctl_sysctl_oidfmt, "");


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
STATIC int
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

STATIC int
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
	error = sysctl_root(TRUE, FALSE, NULL, 0, name, namelen, &req);

	if (error && error != ENOMEM)
		return (error);

	if (oldlenp)
		*oldlenp = req.oldidx;

	return (error);
}

/*
 * Transfer function to/from user space.
 */
STATIC int
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

STATIC int
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
sysctl_root(boolean_t from_kernel, boolean_t string_is_canonical, char *namestring, size_t namestringlen, int *name, u_int namelen, struct sysctl_req *req)
{
	u_int indx;
	int i;
	struct sysctl_oid *oid;
	struct sysctl_oid_list *lsp = &sysctl__children;
	int error;
	boolean_t unlocked_node_found = FALSE;
	boolean_t namestring_started = FALSE;

	/* Get the read lock on the geometry */
	lck_rw_lock_shared(sysctl_geometry_lock);

	if (string_is_canonical) {
		/* namestring is actually canonical, name/namelen needs to be populated */
		error = name2oid(namestring, name, &namelen);
		if (error) {
			goto err;
		}
	}
	
	oid = SLIST_FIRST(lsp);

	indx = 0;
	while (oid && indx < CTL_MAXNAME) {
		if (oid->oid_number == name[indx]) {
			
			if (!from_kernel && !string_is_canonical) {
				if (namestring_started) {
					if (strlcat(namestring, ".", namestringlen) >= namestringlen) {
						error = ENAMETOOLONG;
						goto err;
					}
				}

				if (strlcat(namestring, oid->oid_name, namestringlen) >= namestringlen) {
					error = ENAMETOOLONG;
					goto err;
				}
				namestring_started = TRUE;
			}
			
			indx++;
			if (!(oid->oid_kind & CTLFLAG_LOCKED))
			{
				unlocked_node_found = TRUE;
			}
			if (oid->oid_kind & CTLFLAG_NOLOCK)
				req->lock = 0;
			/*
			 * For SYSCTL_PROC() functions which are for sysctl's
			 * which have parameters at the end of their OID
			 * space, you need to OR CTLTYPE_NODE into their
			 * access value.
			 *
			 * NOTE: For binary backward compatibility ONLY! Do
			 * NOT add new sysctl's that do this!  Existing
			 * sysctl's which do this will eventually have
			 * compatibility code in user space, and this method
			 * will become unsupported.
			 */
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
	
	/*
	 * indx is the index of the first remaining OID name,
	 * for sysctls that take them as arguments
	 */
	if (!from_kernel && !string_is_canonical && (indx < namelen)) {
		char tempbuf[10];
		u_int indx2;
		
		for (indx2 = indx; indx2 < namelen; indx2++) {
			snprintf(tempbuf, sizeof(tempbuf), "%d",name[indx2]);
			
			if (namestring_started) {
				if (strlcat(namestring, ".", namestringlen) >= namestringlen) {
					error = ENAMETOOLONG;
					goto err;
				}
			}
			
			if (strlcat(namestring, tempbuf, namestringlen) >= namestringlen) {
				error = ENAMETOOLONG;
				goto err;
			}
			namestring_started = TRUE;
		}
	}
	
	/* If writing isn't allowed */
	if (req->newptr && (!(oid->oid_kind & CTLFLAG_WR) ||
			    ((oid->oid_kind & CTLFLAG_SECURE) && securelevel > 0))) {
		error = (EPERM);
		goto err;
	}

	/*
	 * If we're inside the kernel, the OID must be marked as kernel-valid.
	 */
	if (from_kernel && !(oid->oid_kind & CTLFLAG_KERN))
	{
		error = (EPERM);
		goto err;
	}

	/*
	 * This is where legacy enforcement of permissions occurs.  If the
	 * flag does not say CTLFLAG_ANYBODY, then we prohibit anyone but
	 * root from writing new values down.  If local enforcement happens
	 * at the leaf node, then it needs to be set as CTLFLAG_ANYBODY.  In
	 * addition, if the leaf node is set this way, then in order to do
	 * specific enforcement, it has to be of type SYSCTL_PROC.
	 */
	if (!(oid->oid_kind & CTLFLAG_ANYBODY) &&
	    req->newptr && req->p &&
	    (error = proc_suser(req->p)))
		goto err;

	if (!oid->oid_handler) {
	    error = EINVAL;
		goto err;
	}

	/*
	 * Reference the OID and drop the geometry lock; this prevents the
	 * OID from being deleted out from under the handler call, but does
	 * not prevent other calls into handlers or calls to manage the
	 * geometry elsewhere from blocking...
	 */
	OSAddAtomic(1, &oid->oid_refcnt);

	lck_rw_done(sysctl_geometry_lock);

#if CONFIG_MACF
	if (!from_kernel) {
		error = mac_system_check_sysctlbyname(kauth_cred_get(),
						      namestring,
						      name,
						      namelen,
						      req->oldptr,
						      req->oldlen,
						      req->newptr,
						      req->newlen);
		if (error)
			goto dropref;
	}
#endif
	
	/*
	 * ...however, we still have to grab the mutex for those calls which
	 * may be into code whose reentrancy is protected by it.
	 */
	if (unlocked_node_found)
	{
		lck_mtx_lock(sysctl_unlocked_node_lock);
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

	if (unlocked_node_found)
	{
		lck_mtx_unlock(sysctl_unlocked_node_lock);
	}

#if CONFIG_MACF
	/* only used from another CONFIG_MACF block */
dropref:
#endif

	/*
	 * This is tricky... we re-grab the geometry lock in order to drop
	 * the reference and wake on the address; since the geometry
	 * lock is a reader/writer lock rather than a mutex, we have to
	 * wake on all apparent 1->0 transitions.  This abuses the drop
	 * after the reference decrement in order to wake any lck_rw_sleep()
	 * in progress in sysctl_unregister_oid() that slept because of a
	 * non-zero reference count.
	 *
	 * Note:	OSAddAtomic() is defined to return the previous value;
	 *		we use this and the fact that the lock itself is a
	 *		barrier to avoid waking every time through on "hot"
	 *		OIDs.
	 */
	lck_rw_lock_shared(sysctl_geometry_lock);
	if (OSAddAtomic(-1, &oid->oid_refcnt) == 1)
		wakeup(&oid->oid_refcnt);

err:
	lck_rw_done(sysctl_geometry_lock);
	return (error);
}

void sysctl_create_user_req(struct sysctl_req *req, struct proc *p, user_addr_t oldp,
							size_t oldlen, user_addr_t newp, size_t newlen)
{
	bzero(req, sizeof(*req));
	
	req->p = p;
	
	req->oldlen = oldlen;
	req->oldptr = oldp;
	
	if (newlen) {
		req->newlen = newlen;
		req->newptr = newp;
	}
	
	req->oldfunc = sysctl_old_user;
	req->newfunc = sysctl_new_user;
	req->lock = 1;

	return;
}

int
sysctl(proc_t p, struct sysctl_args *uap, __unused int32_t *retval)
{
	int error;
	size_t oldlen = 0, newlen;
	int name[CTL_MAXNAME];
	struct sysctl_req req;
	char *namestring;
	size_t namestringlen = MAXPATHLEN;
	
	/*
	 * all top-level sysctl names are non-terminal
	 */
	if (uap->namelen > CTL_MAXNAME || uap->namelen < 2)
		return (EINVAL);
	error = copyin(uap->name, &name[0], uap->namelen * sizeof(int));
	if (error)
		return (error);
	
	AUDIT_ARG(ctlname, name, uap->namelen);
	
	if (uap->newlen > SIZE_T_MAX)
		return (EINVAL);
	newlen = (size_t)uap->newlen;
	
	if (uap->oldlenp != USER_ADDR_NULL) {
		uint64_t	oldlen64 = fuulong(uap->oldlenp);

		/*
		 * If more than 4G, clamp to 4G
		 */
		if (oldlen64 > SIZE_T_MAX)
			oldlen = SIZE_T_MAX;
		else
			oldlen = (size_t)oldlen64;
	}
	
	sysctl_create_user_req(&req, p, uap->old, oldlen, uap->new, newlen);

	/* Guess that longest length for the passed-in MIB, if we can be more aggressive than MAXPATHLEN */
	if (uap->namelen == 2) {
		if (name[0] == CTL_KERN && name[1] < KERN_MAXID) {
			namestringlen = 32; /* "kern.speculative_reads_disabled" */
		} else if (name[0] == CTL_HW && name[1] < HW_MAXID) {
			namestringlen = 32; /* "hw.cachelinesize_compat" */
		}
	}			

	MALLOC(namestring, char *, namestringlen, M_TEMP, M_WAITOK);
	if (!namestring) {
	    oldlen = 0;
	    goto err;
	}

	error = userland_sysctl(FALSE, namestring, namestringlen, name, uap->namelen, &req, &oldlen);
	
	FREE(namestring, M_TEMP);
	
	if ((error) && (error != ENOMEM))
		return (error);
	
err:
	if (uap->oldlenp != USER_ADDR_NULL)
		error = suulong(uap->oldlenp, oldlen);
	
	return (error);
}

int
sysctlbyname(proc_t p, struct sysctlbyname_args *uap, __unused int32_t *retval)
{
	int error;
	size_t oldlen = 0, newlen;
	char *name;
	size_t namelen = 0;
	struct sysctl_req req;
	int oid[CTL_MAXNAME];

	if (uap->namelen >= MAXPATHLEN)	/* XXX arbitrary, undocumented */
		return (ENAMETOOLONG);
	namelen = (size_t)uap->namelen;
	
	MALLOC(name, char *, namelen+1, M_TEMP, M_WAITOK);
	if (!name)
	    return ENOMEM;

	error = copyin(uap->name, name, namelen);
	if (error) {
		FREE(name, M_TEMP);
		return (error);
	}
	name[namelen] = '\0';

	/* XXX
	 * AUDIT_ARG(ctlname, name, uap->namelen);
	 */
	
	if (uap->newlen > SIZE_T_MAX) {
		FREE(name, M_TEMP);
		return (EINVAL);
	}
	newlen = (size_t)uap->newlen;
	
	if (uap->oldlenp != USER_ADDR_NULL) {
		uint64_t	oldlen64 = fuulong(uap->oldlenp);
		
		/*
		 * If more than 4G, clamp to 4G
		 */
		if (oldlen64 > SIZE_T_MAX)
			oldlen = SIZE_T_MAX;
		else
			oldlen = (size_t)oldlen64;
	}
	
	sysctl_create_user_req(&req, p, uap->old, oldlen, uap->new, newlen);

	error = userland_sysctl(TRUE, name, namelen+1, oid, CTL_MAXNAME, &req, &oldlen);
	
	FREE(name, M_TEMP);

	if ((error) && (error != ENOMEM))
		return (error);
	
	if (uap->oldlenp != USER_ADDR_NULL)
		error = suulong(uap->oldlenp, oldlen);
	
	return (error);
}

/*
 * This is used from various compatibility syscalls too.  That's why name
 * must be in kernel space.
 */
int
userland_sysctl(boolean_t string_is_canonical,
				char *namestring, size_t namestringlen,
				int *name, u_int namelen, struct sysctl_req *req,
                size_t *retval)
{
	int error = 0;
	struct sysctl_req req2;

	do {
	    /* if EAGAIN, reset output cursor */
	    req2 = *req;
	    if (!string_is_canonical)
	        namestring[0] = '\0';

	    error = sysctl_root(FALSE, string_is_canonical, namestring, namestringlen, name, namelen, &req2);
	} while (error == EAGAIN);

	if (error && error != ENOMEM)
		return (error);

	if (retval) {
		if (req2.oldptr && req2.oldidx > req2.oldlen)
			*retval = req2.oldlen;
		else
			*retval = req2.oldidx;
	}
	return (error);
}

/*
 * Kernel versions of the userland sysctl helper functions.
 *
 * These allow sysctl to be used in the same fashion in both
 * userland and the kernel.
 *
 * Note that some sysctl handlers use copyin/copyout, which
 * may not work correctly.
 *
 * The "sysctlbyname" KPI for use by kexts is aliased to this function.
 */

int
kernel_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen)
{
	int oid[CTL_MAXNAME];
	int name2mib_oid[2];
	int error;
	size_t oidlen;

	/* look up the OID with magic service node */
	name2mib_oid[0] = 0;
	name2mib_oid[1] = 3;

	oidlen = sizeof(oid);
	error = kernel_sysctl(current_proc(), name2mib_oid, 2, oid, &oidlen, __DECONST(void *, name), strlen(name));
	oidlen /= sizeof(int);
	
	/* now use the OID */
	if (error == 0)
		error = kernel_sysctl(current_proc(), oid, oidlen, oldp, oldlenp, newp, newlen);
	return(error);
}

