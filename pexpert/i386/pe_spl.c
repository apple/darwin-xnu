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
#include <pexpert/protos.h>


typedef unsigned long	spl_t;

spl_t	PE_set_spl(spl_t x);

spl_t splhi() { return PE_set_spl(8); }
spl_t splhigh() { return PE_set_spl(8); }
spl_t splclock() { return PE_set_spl(8); }
spl_t splvm() { return PE_set_spl(8); }
spl_t splsched() { return 	PE_set_spl(8); }
spl_t splimp()	{ return PE_set_spl(6); }
void	splx(spl_t x) { (void) PE_set_spl(x); }
spl_t splnet() { return PE_set_spl(6); }
void  spllo() { (void) PE_set_spl(0); }
spl_t spl1() { return PE_set_spl(1); }
spl_t spl2() { return PE_set_spl(2); }
spl_t spl3() { return PE_set_spl(3); }
spl_t spl4() { return PE_set_spl(4); }
spl_t spl5() { return PE_set_spl(5); }
spl_t spl6() { return PE_set_spl(6); }
spl_t splbio() { return	PE_set_spl(5); }
spl_t spltty() { return	PE_set_spl(6); }

spl_t sploff() { return PE_set_spl(8); }
void splon(spl_t x) { (void) PE_set_spl(x); }

spl_t PE_set_spl(spl_t lvl)
{
  spl_t old_level;
  int   mycpu;

  
  __asm__ volatile("cli");

  mycpu = cpu_number();
  old_level = cpu_data[mycpu].spl_level;
  cpu_data[mycpu].spl_level = lvl ;
  
  if (!lvl) __asm__ volatile("sti");
  
  return old_level;
}

void PE_set_spl_no_interrupt(spl_t lvl)
{
  int mycpu;

  __asm__ volatile("cli");

  mycpu = cpu_number();
  cpu_data[mycpu].spl_level = lvl ;

  return;
}
  
