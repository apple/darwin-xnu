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
        return(0);
}

unsigned
splhigh(
	void)
{
        return(0);
}

unsigned
splsched(
	void)
{
        return(0);
}

unsigned
splclock (
	void)
{
        return(0);
}

unsigned
splpower (
	void)
{
        return(0);
}

unsigned
splvm(
	void)
{
        return(0);
}

unsigned
splbio (
	void)
{
        return(0);
}

unsigned
splimp(
	void)
{
        return(0);
}

unsigned
spltty(void)
{
        return(0);
}

unsigned
splnet(
	void)
{
       return(0);
}

unsigned
splsoftclock(void)
{
        return(0);
}

void
spllo(void)
{
        return;
}

void
spl0(void)
{
        return;
}

void
spln(unsigned t)
{
        return;
}

void
splx(unsigned l)
{
       return;
}

void
splon(unsigned l)
{
       return;
}

