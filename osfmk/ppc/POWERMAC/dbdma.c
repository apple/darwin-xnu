/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 * 
 */

#include <platforms.h>

#include <ppc/proc_reg.h> /* For isync */
#include <mach_debug.h>
#include <kern/assert.h>
#include <kern/cpu_number.h>
#include <kern/spl.h>
#include <mach/mach_types.h>
#include <types.h>
#include <pexpert/ppc/powermac.h>
#include <ppc/io_map_entries.h>
#include <pexpert/ppc/dbdma.h>


static int	dbdma_alloc_index = 0;
dbdma_command_t	*dbdma_alloc_commands = NULL;

void
dbdma_start(dbdma_regmap_t *dmap, dbdma_command_t *commands)
{
	unsigned long addr = kvtophys((vm_offset_t) commands);

	if (addr & 0xf)
		panic("dbdma_start command structure not 16-byte aligned");

	dmap->d_intselect = 0xff;	/* Endian magic - clear out interrupts */
	DBDMA_ST4_ENDIAN(&dmap->d_control, 
			 DBDMA_CLEAR_CNTRL( (DBDMA_CNTRL_ACTIVE	|
					     DBDMA_CNTRL_DEAD	|
					     DBDMA_CNTRL_WAKE	|
					     DBDMA_CNTRL_FLUSH	|
					     DBDMA_CNTRL_PAUSE	|
					     DBDMA_CNTRL_RUN      )));      
	eieio();
     
	while (DBDMA_LD4_ENDIAN(&dmap->d_status) & DBDMA_CNTRL_ACTIVE)
		eieio();

	dmap->d_cmdptrhi = 0;	eieio();/* 64-bit not yet */
	DBDMA_ST4_ENDIAN(&dmap->d_cmdptrlo, addr); eieio();

	DBDMA_ST4_ENDIAN(&dmap->d_control, DBDMA_SET_CNTRL(DBDMA_CNTRL_RUN));
	eieio();

}

void
dbdma_stop(dbdma_regmap_t *dmap)
{
	DBDMA_ST4_ENDIAN(&dmap->d_control, DBDMA_CLEAR_CNTRL(DBDMA_CNTRL_RUN) |
			  DBDMA_SET_CNTRL(DBDMA_CNTRL_FLUSH)); eieio();

	while (DBDMA_LD4_ENDIAN(&dmap->d_status) & (DBDMA_CNTRL_ACTIVE|DBDMA_CNTRL_FLUSH))
		eieio();
}

void
dbdma_flush(dbdma_regmap_t *dmap)
{
	DBDMA_ST4_ENDIAN(&dmap->d_control,DBDMA_SET_CNTRL(DBDMA_CNTRL_FLUSH));
	eieio();

	while (DBDMA_LD4_ENDIAN(&dmap->d_status) & (DBDMA_CNTRL_FLUSH))
		eieio();
}

void
dbdma_reset(dbdma_regmap_t *dmap)
{
	DBDMA_ST4_ENDIAN(&dmap->d_control, 
			 DBDMA_CLEAR_CNTRL( (DBDMA_CNTRL_ACTIVE	|
					     DBDMA_CNTRL_DEAD	|
					     DBDMA_CNTRL_WAKE	|
					     DBDMA_CNTRL_FLUSH	|
					     DBDMA_CNTRL_PAUSE	|
					     DBDMA_CNTRL_RUN      )));      
	eieio();

	while (DBDMA_LD4_ENDIAN(&dmap->d_status) & DBDMA_CNTRL_RUN)
		eieio();
}

void
dbdma_continue(dbdma_regmap_t *dmap)
{
	DBDMA_ST4_ENDIAN(&dmap->d_control, DBDMA_SET_CNTRL(DBDMA_CNTRL_RUN|DBDMA_CNTRL_WAKE) | DBDMA_CLEAR_CNTRL(DBDMA_CNTRL_PAUSE|DBDMA_CNTRL_DEAD));
	eieio();
}

void
dbdma_pause(dbdma_regmap_t *dmap)
{
	DBDMA_ST4_ENDIAN(&dmap->d_control,DBDMA_SET_CNTRL(DBDMA_CNTRL_PAUSE));
	eieio();

	while (DBDMA_LD4_ENDIAN(&dmap->d_status) & DBDMA_CNTRL_ACTIVE)
		eieio();
}

dbdma_command_t	*
dbdma_alloc(int count)
{
	dbdma_command_t	*dbdmap;

	/*
	 * For now, we assume that dbdma_alloc() is called only when
	 * the system is bootstrapping, i.e. before the other CPUs
	 * are activated...
	 * If that's not the case, we need to protect the global
	 * variables here.
	 */
	assert(cpu_number() == master_cpu);

	if (dbdma_alloc_index == 0) 
		dbdma_alloc_commands = (dbdma_command_t *) io_map(0, PAGE_SIZE);
	if ((dbdma_alloc_index+count) >= PAGE_SIZE / sizeof(dbdma_command_t)) 
		panic("Too many dbdma command structures!");

	dbdmap = &dbdma_alloc_commands[dbdma_alloc_index];
	dbdma_alloc_index += count;
	return	dbdmap;
}
