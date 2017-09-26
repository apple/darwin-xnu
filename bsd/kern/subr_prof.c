/*
 * Copyright (c) 2000-2008 Apple Computer, Inc. All rights reserved.
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
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*-
 * Copyright (c) 1982, 1986, 1993
 *	The Regents of the University of California.  All rights reserved.
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
 *	@(#)subr_prof.c	8.3 (Berkeley) 9/23/93
 */

#ifdef GPROF
#include <libkern/kernel_mach_header.h>
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc_internal.h>
#include <sys/user.h>
#include <machine/machine_routines.h>

#include <sys/mount_internal.h>
#include <sys/sysproto.h>

#include <mach/mach_types.h>
#include <kern/kern_types.h>
#include <kern/cpu_number.h>
#include <kern/kalloc.h>

#ifdef GPROF
#include <sys/malloc.h>
#include <sys/gmon.h>

extern int sysctl_doprof(int *, u_int, user_addr_t, size_t *, 
		user_addr_t, size_t newlen);
extern int sysctl_struct(user_addr_t, size_t *,
		user_addr_t, size_t, void *, int);

lck_spin_t * mcount_lock;
lck_grp_t * mcount_lock_grp;
lck_attr_t * mcount_lock_attr;

/*
 * Froms is actually a bunch of unsigned shorts indexing tos
 */
struct gmonparam _gmonparam = { .state = GMON_PROF_OFF };

/*
 * This code uses 32 bit mach object segment information from the currently
 * running kernel.
 */
void
kmstartup(void)
{
	tostruct_t *cp;
	kernel_segment_command_t	*sgp;	/* 32 bit mach object file segment */
	struct gmonparam *p = &_gmonparam;
	
	sgp = getsegbyname("__TEXT");
	p->lowpc = (u_int32_t)sgp->vmaddr;
	p->highpc = (u_int32_t)(sgp->vmaddr + sgp->vmsize);
	
	/*
	 * Round lowpc and highpc to multiples of the density we're using
	 * so the rest of the scaling (here and in gprof) stays in ints.
	 */
	p->lowpc = ROUNDDOWN(p->lowpc, HISTFRACTION * sizeof(HISTCOUNTER));
	p->highpc = ROUNDUP(p->highpc, HISTFRACTION * sizeof(HISTCOUNTER));
	p->textsize = p->highpc - p->lowpc;
	printf("Profiling kernel, textsize=%lu [0x%016lx..0x%016lx]\n",
	       p->textsize, p->lowpc, p->highpc);
	p->kcountsize = p->textsize / HISTFRACTION;
	p->hashfraction = HASHFRACTION;
	p->fromssize = p->textsize / HASHFRACTION;
	p->tolimit = p->textsize * ARCDENSITY / 100;
	if (p->tolimit < MINARCS)
		p->tolimit = MINARCS;
	else if (p->tolimit > MAXARCS)
		p->tolimit = MAXARCS;
	p->tossize = p->tolimit * sizeof(tostruct_t);
	/* Why not use MALLOC with M_GPROF ? */
	cp = (tostruct_t *)kalloc(p->kcountsize + p->fromssize + p->tossize);
	if (cp == 0) {
		printf("No memory for profiling.\n");
		return;
	}
	bzero(cp, p->kcountsize + p->tossize + p->fromssize);
	p->tos = cp;
	cp = (tostruct_t *)((vm_offset_t)cp + p->tossize);
	p->kcount = (u_short *)cp;
	cp = (tostruct_t *)((vm_offset_t)cp + p->kcountsize);
	p->froms = (u_short *)cp;
	
	mcount_lock_grp = lck_grp_alloc_init("MCOUNT", LCK_GRP_ATTR_NULL);
	mcount_lock_attr = lck_attr_alloc_init();
	mcount_lock = lck_spin_alloc_init(mcount_lock_grp, mcount_lock_attr);

}

/*
 * XXX		These should be broken out into per-argument OID values,
 * XXX		since there are no sub-OID parameter values, but unfortunately
 * XXX		there is barely enough time for an initial conversion.
 *
 * Note:	These items appear to be read/write.
 */
STATIC int
sysctl_doprofhandle SYSCTL_HANDLER_ARGS
{
sysctl_doprof(int *name, u_int namelen, user_addr_t oldp, size_t *oldlenp, 
              user_addr_t newp, size_t newlen)
{
	__unused int cmd = oidp->oid_arg2;	/* subcommand*/
	int *name = arg1;		/* oid element argument vector */
	int namelen = arg2;		/* number of oid element arguments */
	user_addr_t oldp = req->oldptr;	/* user buffer copy out address */
	size_t *oldlenp = req->oldlen;	/* user buffer copy out size */
	user_addr_t newp = req->newptr;	/* user buffer copy in address */
	size_t newlen = req->newlen;	/* user buffer copy in size */

	struct gmonparam *gp = &_gmonparam;
	int error = 0;

	/* all sysctl names at this level are terminal */
	if (namelen != 1)
		return (ENOTDIR);		/* overloaded */

	switch (name[0]) {
	case GPROF_STATE:
		error = sysctl_int(oldp, oldlenp, newp, newlen, &gp->state);
		if (error)
			break;
		if (gp->state == GMON_PROF_OFF)
			stopprofclock(kernproc);
		else
			startprofclock(kernproc);
		break;
	case GPROF_COUNT:
		error = sysctl_struct(oldp, oldlenp, newp, newlen, 
		                      gp->kcount, gp->kcountsize);
		break;
	case GPROF_FROMS:
		error = sysctl_struct(oldp, oldlenp, newp, newlen,
		                      gp->froms, gp->fromssize);
		break;
	case GPROF_TOS:
		error = sysctl_struct(oldp, oldlenp, newp, newlen,
		                      gp->tos, gp->tossize);
		break;
	case GPROF_GMONPARAM:
		error = sysctl_rdstruct(oldp, oldlenp, newp, gp, sizeof *gp);
		break;
	default:
		error = ENOTSUP;
		break;
	}

	/* adjust index so we return the right required/consumed amount */
	if (!error)
		req->oldidx += req->oldlen;

	return(error);
}
SYSCTL_PROC(_kern, KERN_PROF, prof, STLFLAG_NODE|CTLFLAG_RW | CTLFLAG_LOCKED,
	0,			/* Pointer argument (arg1) */
	0,			/* Integer argument (arg2) */
	sysctl_doprofhandle,	/* Handler function */
	NULL,			/* No explicit data */
	"");


/*
 * mcount() called with interrupts disabled.
 */
void
mcount(
    uintptr_t frompc,
    uintptr_t selfpc
)
{
    unsigned short *frompcindex;
	tostruct_t *top, *prevtop;
	struct gmonparam *p = &_gmonparam;
	long toindex;

    /*
     * check that we are profiling
     * and that we aren't recursively invoked.
     */
    if (p->state != GMON_PROF_ON)
        return;

	lck_spin_lock(mcount_lock);

	/*
	 *	check that frompcindex is a reasonable pc value.
	 *	for example:	signal catchers get called from the stack,
	 *			not from text space.  too bad.
	 */
	frompc -= p->lowpc;
	if (frompc > p->textsize)
		goto done;

	frompcindex = &p->froms[frompc / (p->hashfraction * sizeof(*p->froms))];
	toindex = *frompcindex;
	if (toindex == 0) {
		/*
		 *	first time traversing this arc
		 */
		toindex = ++p->tos[0].link;
		if (toindex >= p->tolimit) {
            /* halt further profiling */
			goto overflow;
		}
		*frompcindex = toindex;
		top = &p->tos[toindex];
		top->selfpc = selfpc;
		top->count = 1;
		top->link = 0;
		goto done;
	}
	top = &p->tos[toindex];
	if (top->selfpc == selfpc) {
		/*
		 *	arc at front of chain; usual case.
		 */
		top->count++;
		goto done;
	}
	/*
	 *	have to go looking down chain for it.
	 *	top points to what we are looking at,
	 *	prevtop points to previous top.
	 *	we know it is not at the head of the chain.
	 */
	for (; /* goto done */; ) {
		if (top->link == 0) {
			/*
			 *	top is end of the chain and none of the chain
			 *	had top->selfpc == selfpc.
			 *	so we allocate a new tostruct
			 *	and link it to the head of the chain.
			 */
			toindex = ++p->tos[0].link;
			if (toindex >= p->tolimit) {
				goto overflow;
			}
			top = &p->tos[toindex];
			top->selfpc = selfpc;
			top->count = 1;
			top->link = *frompcindex;
			*frompcindex = toindex;
			goto done;
		}
		/*
		 *	otherwise, check the next arc on the chain.
		 */
		prevtop = top;
		top = &p->tos[top->link];
		if (top->selfpc == selfpc) {
			/*
			 *	there it is.
			 *	increment its count
			 *	move it to the head of the chain.
			 */
			top->count++;
			toindex = prevtop->link;
			prevtop->link = top->link;
			top->link = *frompcindex;
			*frompcindex = toindex;
			goto done;
		}

	}
done:
	lck_spin_unlock(mcount_lock);
	return;

overflow:
    p->state = GMON_PROF_ERROR;
        lck_spin_unlock(mcount_lock);
	printf("mcount: tos overflow\n");
	return;
}

#endif /* GPROF */

#define PROFILE_LOCK(x)
#define PROFILE_UNLOCK(x)


/*
 * Scale is a fixed-point number with the binary point 16 bits
 * into the value, and is <= 1.0.  pc is at most 32 bits, so the
 * intermediate result is at most 48 bits.
 */
//K64todo - this doesn't fit into 64 bit any more, it needs 64+16
#define PC_TO_INDEX(pc, prof) \
	((user_addr_t)(((u_quad_t)((pc) - (prof)->pr_off) * \
			(u_quad_t)((prof)->pr_scale)) >> 16) & ~1)

/*
 * Collect user-level profiling statistics; called on a profiling tick,
 * when a process is running in user-mode. We use
 * an AST that will vector us to trap() with a context in which copyin
 * and copyout will work.  Trap will then call addupc_task().
 *
 * Note that we may (rarely) not get around to the AST soon enough, and
 * lose profile ticks when the next tick overwrites this one, but in this
 * case the system is overloaded and the profile is probably already
 * inaccurate.
 *
 * We can afford to take faults here.  If the
 * update fails, we simply turn off profiling.
 */
void
addupc_task(struct proc *p, user_addr_t pc, u_int ticks)
{
	user_addr_t off;
	u_short count;

	/* Testing P_PROFIL may be unnecessary, but is certainly safe. */
	if ((p->p_flag & P_PROFIL) == 0 || ticks == 0)
		return;

	if (proc_is64bit(p)) {
        struct user_uprof *prof;
        user_addr_t cell;

        for (prof = &p->p_stats->user_p_prof; prof; prof = prof->pr_next) {
            off = PC_TO_INDEX(pc, prof);
            cell = (prof->pr_base + off);
            if (cell >= prof->pr_base &&
                cell < (prof->pr_size + prof->pr_base)) {
                if (copyin(cell, (caddr_t) &count, sizeof(count)) == 0) {
                    count += ticks;
                    if(copyout((caddr_t) &count, cell, sizeof(count)) == 0)
                        return;
                }
                p->p_stats->user_p_prof.pr_scale = 0;
                stopprofclock(p);
                break;
            }
        }
	}
	else {
        struct uprof *prof;
        short *cell;

        for (prof = &p->p_stats->p_prof; prof; prof = prof->pr_next) {
            off = PC_TO_INDEX(pc,prof);
            cell = (short *)(prof->pr_base + off);
            if (cell >= (short *)prof->pr_base &&
                cell < (short*)(prof->pr_size + prof->pr_base)) {
                if (copyin(CAST_USER_ADDR_T(cell), (caddr_t) &count, sizeof(count)) == 0) {
                    count += ticks;
                    if(copyout((caddr_t) &count, CAST_USER_ADDR_T(cell), sizeof(count)) == 0)
                        return;
                }
                p->p_stats->p_prof.pr_scale = 0;
                stopprofclock(p);
                break;
            }
        }
	}
}
