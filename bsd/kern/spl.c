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
#include <machine/machine_routines.h>
#include <machine/spl.h>
#include <kern/thread.h>

unsigned
sploff(
	void)
{
        if(thread_funnel_get() == THR_FUNNEL_NULL)
                panic("%s not under funnel", "sploff()");
        return(0);
}

unsigned
splhigh(
	void)
{
        if(thread_funnel_get() == THR_FUNNEL_NULL)
                panic("%s not under funnel", "splhigh()");
        return(0);
}

unsigned
splsched(
	void)
{
        if(thread_funnel_get() == THR_FUNNEL_NULL)
                panic("%s not under funnel", "splsched()");
        return(0);
}

unsigned
splclock (
	void)
{
        if(thread_funnel_get() == THR_FUNNEL_NULL)
                panic("%s not under funnel", "splclock()");
        return(0);
}

unsigned
splpower (
	void)
{
        if(thread_funnel_get() == THR_FUNNEL_NULL)
                panic("%s not under funnel", "splpower()");
        return(0);
}

unsigned
splvm(
	void)
{
        if(thread_funnel_get() == THR_FUNNEL_NULL)
                panic("%s not under funnel", "splvm()");
        return(0);
}

unsigned
splbio (
	void)
{
        if(thread_funnel_get() == THR_FUNNEL_NULL)
                panic("%s not under funnel", "splbio()");
        return(0);
}

unsigned
splimp(
	void)
{
        if(thread_funnel_get() == THR_FUNNEL_NULL)
                panic("%s not under funnel", "splimp()");
        return(0);
}

unsigned
spltty(void)
{
        if(thread_funnel_get() == THR_FUNNEL_NULL)
                panic("%s not under funnel", "spltty()");
        return(0);
}

unsigned
splnet(
	void)
{
        if(thread_funnel_get() == THR_FUNNEL_NULL)
                panic("%s not under funnel", "splnet()");
       return(0);
}

unsigned
splsoftclock(void)
{
        if(thread_funnel_get() == THR_FUNNEL_NULL)
                panic("%s not under funnel", "splsoftclock()");
        return(0);
}

void
spllo(void)
{
        if(thread_funnel_get() == THR_FUNNEL_NULL)
                panic("%s not under funnel", "spllo()");
        return;
}

void
spl0(void)
{
        if(thread_funnel_get() == THR_FUNNEL_NULL)
                panic("%s not under funnel", "spl0()");
        return;
}

void
spln(unsigned t)
{
        if(thread_funnel_get() == THR_FUNNEL_NULL)
                panic("%s not under funnel", "spln()");
        return;
}

void
splx(unsigned l)
{
        if(thread_funnel_get() == THR_FUNNEL_NULL)
                panic("%s not under funnel", "splx()");
       return;
}

void
splon(unsigned l)
{
        if(thread_funnel_get() == THR_FUNNEL_NULL)
                panic("%s not under funnel", "splon()");
       return;
}
