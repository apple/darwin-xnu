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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <machine/spl.h>

#include <sys/mount.h>

#include <kern/cpu_number.h>

#ifdef GPROF
#include <sys/malloc.h>
#include <sys/gmon.h>
#include <kern/mach_header.h>
#include <machine/profile.h>

/*
 * Froms is actually a bunch of unsigned shorts indexing tos
 */
struct gmonparam _gmonparam = { GMON_PROF_OFF };

kmstartup()
{
	char *cp;
	u_long	fromssize, tossize;
	struct segment_command		*sgp;
	struct gmonparam *p = &_gmonparam;
	
	sgp = getsegbyname("__TEXT");
	p->lowpc = (u_long)sgp->vmaddr;
	p->highpc = (u_long)(sgp->vmaddr + sgp->vmsize);
	
	/*
	 * Round lowpc and highpc to multiples of the density we're using
	 * so the rest of the scaling (here and in gprof) stays in ints.
	 */
	p->lowpc = ROUNDDOWN(p->lowpc, HISTFRACTION * sizeof(HISTCOUNTER));
	p->highpc = ROUNDUP(p->highpc, HISTFRACTION * sizeof(HISTCOUNTER));
	p->textsize = p->highpc - p->lowpc;
	printf("Profiling kernel, textsize=%d [0x%08x..0x%08x]\n",
	       p->textsize, p->lowpc, p->highpc);
	p->kcountsize = p->textsize / HISTFRACTION;
	p->hashfraction = HASHFRACTION;
	p->fromssize = p->textsize / HASHFRACTION;
	p->tolimit = p->textsize * ARCDENSITY / 100;
	if (p->tolimit < MINARCS)
		p->tolimit = MINARCS;
	else if (p->tolimit > MAXARCS)
		p->tolimit = MAXARCS;
	p->tossize = p->tolimit * sizeof(struct tostruct);
	/* Why not use MALLOC with M_GPROF ? */
	cp = (char *)kalloc(p->kcountsize + p->fromssize + p->tossize);
	if (cp == 0) {
		printf("No memory for profiling.\n");
		return;
	}
	bzero(cp, p->kcountsize + p->tossize + p->fromssize);
	p->tos = (struct tostruct *)cp;
	cp += p->tossize;
	p->kcount = (u_short *)cp;
	cp += p->kcountsize;
	p->froms = (u_short *)cp;
}

/*
 * Return kernel profiling information.
 */
int
sysctl_doprof(name, namelen, oldp, oldlenp, newp, newlen)
	int *name;
	u_int namelen;
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
{
	struct gmonparam *gp = &_gmonparam;
	int error;

	/* all sysctl names at this level are terminal */
	if (namelen != 1)
		return (ENOTDIR);		/* overloaded */

	switch (name[0]) {
	case GPROF_STATE:
		error = sysctl_int(oldp, oldlenp, newp, newlen, &gp->state);
		if (error)
			return (error);
		if (gp->state == GMON_PROF_OFF)
			stopprofclock(kernproc);
		else
			startprofclock(kernproc);
		return (0);
	case GPROF_COUNT:
		return (sysctl_struct(oldp, oldlenp, newp, newlen,
		    gp->kcount, gp->kcountsize));
	case GPROF_FROMS:
		return (sysctl_struct(oldp, oldlenp, newp, newlen,
		    gp->froms, gp->fromssize));
	case GPROF_TOS:
		return (sysctl_struct(oldp, oldlenp, newp, newlen,
		    gp->tos, gp->tossize));
	case GPROF_GMONPARAM:
		return (sysctl_rdstruct(oldp, oldlenp, newp, gp, sizeof *gp));
	default:
		return (EOPNOTSUPP);
	}
	/* NOTREACHED */
}


/*
 * mcount() called with interrupts disabled.
 */
void
mcount(
    register u_long frompc,
    register u_long selfpc
)
{
    unsigned short *frompcindex;
	register struct tostruct *top, *prevtop;
	struct gmonparam *p = &_gmonparam;
	register long toindex;
	MCOUNT_INIT;

    /*
     * check that we are profiling
     * and that we aren't recursively invoked.
     */
    if (p->state != GMON_PROF_ON)
        return;

	MCOUNT_ENTER;

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
	MCOUNT_EXIT;
	return;

overflow:
    p->state = GMON_PROF_ERROR;
	MCOUNT_EXIT;
	printf("mcount: tos overflow\n");
	return;
}

#endif /* GPROF */

#if NCPUS > 1
#define PROFILE_LOCK(x)		simple_lock(x)
#define PROFILE_UNLOCK(x)	simple_unlock(x)
#else
#define PROFILE_LOCK(x)
#define PROFILE_UNLOCK(x)
#endif

struct profil_args {
	short	*bufbase;
	u_int bufsize;
	u_int pcoffset;
	u_int pcscale;
};
int
profil(p, uap, retval)
	struct proc *p;
	register struct profil_args *uap;
	register_t *retval;
{
	register struct uprof *upp = &p->p_stats->p_prof;
	struct uprof *upc, *nupc;
	int s;

	if (uap->pcscale > (1 << 16))
		return (EINVAL);
	if (uap->pcscale == 0) {
		stopprofclock(p);
		return (0);
	}

	/* Block profile interrupts while changing state. */
	s = splstatclock();
	PROFILE_LOCK(&upp->pr_lock);
	upp->pr_base = (caddr_t)uap->bufbase;
	upp->pr_size = uap->bufsize;
	upp->pr_off = uap->pcoffset;
	upp->pr_scale = uap->pcscale;

	/* remove buffers previously allocated with add_profil() */
	for (upc = upp->pr_next; upc; upc = nupc) {
		nupc = upc->pr_next;
		kfree(upc, sizeof (struct uprof));
	}

	upp->pr_next = 0;
	PROFILE_UNLOCK(&upp->pr_lock);
	startprofclock(p);
	splx(s);
	return(0);
}

struct add_profile_args {
	short	*bufbase;
	u_int bufsize;
	u_int pcoffset;
	u_int pcscale;
};
int
add_profil(p, uap, retval)
	struct proc *p;
	register struct add_profile_args *uap;
	register_t *retval;
{
	struct uprof *upp = &p->p_stats->p_prof, *upc;
	int s;

	if (upp->pr_scale == 0)
		return (0);
	s = splstatclock();
	upc = (struct uprof *) kalloc(sizeof (struct uprof));
	upc->pr_base = (caddr_t)uap->bufbase;
	upc->pr_size = uap->bufsize;
	upc->pr_off = uap->pcoffset;
	upc->pr_scale = uap->pcscale;
	PROFILE_LOCK(&upp->pr_lock);
	upc->pr_next = upp->pr_next;
	upp->pr_next = upc;
	PROFILE_UNLOCK(&upp->pr_lock);
	splx(s);
	return(0);
}

/*
 * Scale is a fixed-point number with the binary point 16 bits
 * into the value, and is <= 1.0.  pc is at most 32 bits, so the
 * intermediate result is at most 48 bits.
 */
#define PC_TO_INDEX(pc, prof) \
	((int)(((u_quad_t)((pc) - (prof)->pr_off) * \
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
addupc_task(p, pc, ticks)
	register struct proc *p;
	register u_long pc;
	u_int ticks;
{
	register struct uprof *prof;
	register short *cell;
	register u_int off;
	u_short count;

	/* Testing P_PROFIL may be unnecessary, but is certainly safe. */
	if ((p->p_flag & P_PROFIL) == 0 || ticks == 0)
		return;

	for (prof = &p->p_stats->p_prof; prof; prof = prof->pr_next) {
		off = PC_TO_INDEX(pc,prof);
		cell = (short *)(prof->pr_base + off);
		if (cell >= (short *)prof->pr_base &&
			cell < (short*)(prof->pr_size + (int) prof->pr_base)) {
			if (copyin((caddr_t)cell, (caddr_t) &count, sizeof(count)) == 0) {
				count += ticks;
				if(copyout((caddr_t) &count, (caddr_t)cell, sizeof(count)) == 0)
					return;
			}
			p->p_stats->p_prof.pr_scale = 0;
			stopprofclock(p);
			break;
		}
	}
}
