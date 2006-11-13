/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
 * http://www.opensource.apple.com/apsl/ and read it before using this 
 * file.
 *
 * The Original Code and all software distributed under the License are 
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER 
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES, 
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT. 
 * Please see the License for the specific language governing rights and 
 * limitations under the License.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
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
#include <sys/proc_internal.h>
#include <sys/user.h>
#include <machine/spl.h>
#include <machine/machine_routines.h>

#include <sys/mount_internal.h>
#include <sys/sysproto.h>

#include <mach/mach_types.h>
#include <kern/kern_types.h>
#include <kern/cpu_number.h>
#include <kern/kalloc.h>

extern boolean_t ml_set_interrupts_enabled(boolean_t enable);

#ifdef GPROF
#include <sys/malloc.h>
#include <sys/gmon.h>
#include <kern/mach_header.h>
#include <machine/profile.h>

lck_spin_t * mcount_lock;
lck_grp_t * mcount_lock_grp;
lck_attr_t * mcount_lock_attr;

/*
 * Froms is actually a bunch of unsigned shorts indexing tos
 */
struct gmonparam _gmonparam = { GMON_PROF_OFF };

/*
 * This code uses 32 bit mach object segment information from the currently
 * running kernel.
 */
void
kmstartup(void)
{
	char *cp;
	u_long	fromssize, tossize;
	struct segment_command	*sgp;	/* 32 bit mach object file segment */
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
	
	mcount_lock_grp = lck_grp_alloc_init("MCOUNT", LCK_GRP_ATTR_NULL);
	mcount_lock_attr = lck_attr_alloc_init();
	mcount_lock = lck_spin_alloc_init(mcount_lock_grp, mcount_lock_attr);

}

/*
 * Return kernel profiling information.
 */
int
sysctl_doprof(int *name, u_int namelen, user_addr_t oldp, size_t *oldlenp, 
              user_addr_t newp, size_t newlen)
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
		return (ENOTSUP);
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

int
profil(struct proc *p, register struct profil_args *uap, __unused register_t *retval)
{
    struct uprof *upp = &p->p_stats->p_prof;
    int s;

	if (uap->pcscale > (1 << 16))
		return (EINVAL);
	if (uap->pcscale == 0) {
		stopprofclock(p);
		return (0);
	}

	/* Block profile interrupts while changing state. */
    s = ml_set_interrupts_enabled(FALSE);	

	if (proc_is64bit(p)) {
        struct user_uprof *user_upp = &p->p_stats->user_p_prof;
    	struct user_uprof *upc, *nupc;
	
	    PROFILE_LOCK(&user_upp->pr_lock);
        user_upp->pr_base = uap->bufbase;
        user_upp->pr_size = uap->bufsize;
        user_upp->pr_off = uap->pcoffset;
	    user_upp->pr_scale = uap->pcscale;
        upp->pr_base = NULL;
        upp->pr_size = 0;
        upp->pr_scale = 0;

        /* remove buffers previously allocated with add_profil() */
        for (upc = user_upp->pr_next; upc; upc = nupc) {
            nupc = upc->pr_next;
            kfree(upc, sizeof (*upc));
        }
        user_upp->pr_next = 0;
	    PROFILE_UNLOCK(&user_upp->pr_lock);
	}
	else {
    	struct uprof *upc, *nupc;
	    
	    PROFILE_LOCK(&upp->pr_lock);
        upp->pr_base = CAST_DOWN(caddr_t, uap->bufbase);
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
	}

	startprofclock(p);
	ml_set_interrupts_enabled(s);
	return(0);
}

int
add_profil(struct proc *p, register struct add_profil_args *uap, __unused register_t *retval)
{
	struct uprof *upp = &p->p_stats->p_prof, *upc;
	struct user_uprof *user_upp = NULL, *user_upc;
	int s;
	boolean_t is64bit = proc_is64bit(p);

	if (is64bit) {
       user_upp = &p->p_stats->user_p_prof;
       if (user_upp->pr_scale == 0)
            return (0);
    }
    else {
        if (upp->pr_scale == 0)
            return (0);
    }

    s = ml_set_interrupts_enabled(FALSE);	
    
	if (is64bit) {
        user_upc = (struct user_uprof *) kalloc(sizeof (struct user_uprof));
        user_upc->pr_base = uap->bufbase;
        user_upc->pr_size = uap->bufsize;
        user_upc->pr_off = uap->pcoffset;
        user_upc->pr_scale = uap->pcscale;
        PROFILE_LOCK(&user_upp->pr_lock);
        user_upc->pr_next = user_upp->pr_next;
        user_upp->pr_next = user_upc;
        PROFILE_UNLOCK(&user_upp->pr_lock);
    }
    else {
        upc = (struct uprof *) kalloc(sizeof (struct uprof));
        upc->pr_base = CAST_DOWN(caddr_t, uap->bufbase);
        upc->pr_size = uap->bufsize;
        upc->pr_off = uap->pcoffset;
        upc->pr_scale = uap->pcscale;
        PROFILE_LOCK(&upp->pr_lock);
        upc->pr_next = upp->pr_next;
        upp->pr_next = upc;
        PROFILE_UNLOCK(&upp->pr_lock);
    }
    
	ml_set_interrupts_enabled(s);		
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
	user_addr_t pc;
	u_int ticks;
{
	register u_int off;
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
            off = PC_TO_INDEX(CAST_DOWN(uint, pc),prof);
            cell = (short *)(prof->pr_base + off);
            if (cell >= (short *)prof->pr_base &&
                cell < (short*)(prof->pr_size + (int) prof->pr_base)) {
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
