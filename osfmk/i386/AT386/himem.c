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
 * @OSF_FREE_COPYRIGHT@
 */
/*
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:38  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:39  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.3.17.7  1995/08/21  20:33:13  devrcs
 * 	ri-osc CR1547:  Fix himem buffer translation to cope with non
 * 	page-aligned addresses.
 * 	[1995/08/08  16:51:58  bolinger]
 *
 * Revision 1.3.17.6  1995/02/24  15:51:12  alanl
 * 	DIPC:  Merge from nmk17b2 to nmk18b8.
 * 	Notes:  lock package cleanup.
 * 	[95/01/23            alanl]
 * 	[95/02/24            alanl]
 * 
 * Revision 1.3.17.5  1995/01/26  22:14:52  ezf
 * 	removed extraneous CMU CR
 * 	[1995/01/26  20:24:45  ezf]
 * 
 * Revision 1.3.17.4  1995/01/10  04:51:04  devrcs
 * 	mk6 CR801 - merge up from nmk18b4 to nmk18b7
 * 	* Rev 1.3.17.3  1994/10/21  18:41:39  joe
 * 	  Added ETAP support
 * 	[1994/12/09  20:37:48  dwm]
 * 
 * 	mk6 CR764 - s/spinlock/simple_lock/ (name change only)
 * 	[1994/11/10  05:25:33  dwm]
 * 
 * 	mk6 CR668 - 1.3b26 merge
 * 	* Revision 1.3.5.8  1994/05/06  18:44:06  tmt
 * 	Fix prototypes for new device signatures.
 * 	* Revision 1.3.5.6  1993/12/10  18:08:15  jeffc
 * 	CR10305 -- locking bug in himem_reserve(): change call to
 * 	vm_page_free to VM_PAGE_FREE.
 * 	* Revision 1.3.5.5  1993/11/19  17:56:58  jeffc
 * 	CR10125 -- Uninitialized lock in himem_convert. Add himem_init
 * 	CR9461 -- Locking bug in himem_convert - must retake lock after
 * 	thread_sleep.
 * 	* End1.3merge
 * 	[1994/11/04  09:07:39  dwm]
 * 
 * Revision 1.3.17.1  1994/06/14  03:04:20  toshi
 * 	Merge MK6 and NMK17
 * 	[1994/06/14  01:06:55  toshi]
 * 
 * Revision 1.3.15.2  1994/06/08  21:14:24  dswartz
 * 	Preemption merge.
 * 	[1994/06/08  21:12:29  dswartz]
 * 
 * Revision 1.3.15.1  1994/05/19  20:30:23  dwm
 * 	mk6 CR 74.  Locking bug in himem_reserve(): use VM_PAGE_FREE.
 * 	mk6 CR 9461.  Init hil_lock used by himem_convert();
 * 	retake lock after sleeping.
 * 	[1994/05/19  20:30:07  dwm]
 * 
 * Revision 1.3.11.1  1994/02/09  07:27:07  bernadat
 * 	Added himem_init() for module initialization.
 * 	[93/08/12            paire]
 * 
 * 	Take back hil_lock lock on return from thread_sleep()
 * 	[93/07/16            bernadat]
 * 
 * 	Add vm_page_gobble() calls where needed. (dwm bug #542)
 * 	Change from NORMA_MK14.6 [1993/02/09  22:24:00  dwm]
 * 	[93/07/16            bernadat]
 * 	[94/02/08            bernadat]
 * 
 * Revision 1.3.5.4  1993/08/09  19:37:19  dswartz
 * 	Add ANSI prototypes - CR#9523
 * 	[1993/08/06  17:50:02  dswartz]
 * 
 * Revision 1.3.5.3  1993/08/03  22:21:26  bernard
 * 	CR#9523 - ANSI prototype fixes.
 * 	[1993/08/03  15:34:10  bernard]
 * 
 * Revision 1.3.5.2  1993/06/09  02:25:18  gm
 * 	CR9157 - Find himem.h in the right place.
 * 	[1993/05/28  17:27:23  brezak]
 * 
 * Revision 1.3  1993/04/19  16:09:46  devrcs
 * 	make endif tags ansi compliant/include files
 * 	[1993/02/20  21:46:44  david]
 * 
 * 	Print an appropriate message when going out of HIMEM pages.
 * 	[93/01/26            bernadat]
 * 
 * Revision 1.2  1992/11/25  01:07:08  robert
 * 	integrate changes below for norma_14
 * 	[1992/11/13  19:28:44  robert]
 * 
 * $EndLog$
 */

/*
 * support of memory above 16 Megs for DMA limited to memory
 * below 16 Megs. Copies high memory lo low memory before DMA
 * write operations and does the reverse at completion time for
 * DMA read operations
 */

#include <cpus.h>
#include <platforms.h>
#include <kern/lock.h>
#include <mach/vm_param.h>
#include <vm/vm_page.h>
#include <i386/AT386/himem.h>
#include <kern/kalloc.h>
#include <kern/spl.h>
#include <mach/boolean.h>
#include <kern/misc_protos.h>
#include <i386/AT386/misc_protos.h>

hil_t		hil_head;
decl_simple_lock_data(,hil_lock)

#if	HIMEM_STATS
int himem_request;	/* number of requests */
int himem_used;		/* number of times used */
#endif	/* HIMEM_STATS */

void
himem_init(
	void)
{
	simple_lock_init(&hil_lock, ETAP_VM_HIMEM);
}

/* 
 * Called by drivers, this indicates himem that this driver might need
 * to allocate as many as npages pages in a single I/O DMA transfer
 */

void
himem_reserve(
	int		npages)
{
	register		i = 0;
	vm_page_t		free_head = VM_PAGE_NULL;
	vm_page_t		low;
	hil_t			hil;
	spl_t			ipl;
	extern vm_offset_t	avail_end;

	if (avail_end <= HIGH_MEM)
		return;
	hil = (hil_t)kalloc(npages*sizeof(struct himem_link));
	if (hil == (hil_t)0) 
		panic("himem_reserve: kalloc failed\n");

	for (i=0; i < npages-1; i++)
		(hil+i)->next = hil+i+1;

	/*
	 * This is the only way of getting low physical pages 
	 * wtithout changing VM internals
	 */
	for (i=0; i != npages;) {
		if ((low = vm_page_grab()) == VM_PAGE_NULL)
			panic("No low memory pages for himem\n");
		vm_page_gobble(low); /* mark as consumed internally */
		if (_high_mem_page(low->phys_addr)) {
			low->pageq.next = (queue_entry_t)free_head;
			free_head = low;
		} else {
			(hil+i)->low_page = low->phys_addr;
			i++;
		}
	}

	for (low = free_head; low; low = free_head) {
		free_head = (vm_page_t) low->pageq.next;
		VM_PAGE_FREE(low);
        }

	ipl = splhi();
	simple_lock(&hil_lock);
	(hil+npages-1)->next = hil_head;
	hil_head = hil;
	simple_unlock(&hil_lock);
	splx(ipl);
}

/*
 * Called by driver at DMA initialization time. Converts a high memory
 * physical page to a low memory one. If operation is a write, 
 * [phys_addr, phys_addr+length-1] is copied to new page. Caller must
 * provide a pointer to a pointer to a himem_list. This is used to store
 * all the conversions and is use at completion time to revert the pages.
 * This pointer must point to a null hil_t value for the call on the first
 * page of a DMA transfer.
 */

vm_offset_t
himem_convert(
	vm_offset_t	phys_addr,
	vm_size_t	length,
	int		io_op,
	hil_t		*hil)
{
	hil_t		h;
	spl_t		ipl;
	vm_offset_t	offset = phys_addr & (I386_PGBYTES - 1);

	assert (offset + length <= I386_PGBYTES);

	ipl = splhi();
	simple_lock(&hil_lock);
	while (!(h = hil_head)) { 
		printf("WARNING: out of HIMEM pages\n");
		thread_sleep_simple_lock((event_t)&hil_head,
					 simple_lock_addr(hil_lock),
					 THREAD_UNINT);
		/* hil_lock relocked */
	}
	hil_head = hil_head->next;
	simple_unlock(&hil_lock);
	splx(ipl);
	
	h->high_addr = phys_addr;

	if (io_op == D_WRITE) {
	  bcopy((char *)phystokv(phys_addr), (char *)phystokv(h->low_page + offset),
		length);
	  h->length = 0;
	} else {
	  h->length = length;
	}
	h->offset = offset;

	assert(!*hil || (*hil)->high_addr);

	h->next = *hil;
	*hil = h;
	return(h->low_page + offset);
}

/*
 * Called by driver at DMA completion time. Converts a list of low memory
 * physical page to the original high memory one. If operation was read, 
 * [phys_addr, phys_addr+lenght-1] is copied to original page
 */

void
himem_revert(
	hil_t		hil)
{
	hil_t		next;
	boolean_t	wakeup = FALSE;
	spl_t		ipl;

	while(hil) {
		if (hil->length) {
			bcopy((char *)phystokv(hil->low_page + hil->offset),
				(char *)phystokv(hil->high_addr),
			      hil->length);
		}
		hil->high_addr = 0;
		hil->length = 0;
		hil->offset = 0;
		next = hil->next;
		ipl = splhi();
		simple_lock(&hil_lock);
		if (!(hil->next = hil_head))
			wakeup = TRUE;
		hil_head = hil;
		simple_unlock(&hil_lock);
		splx(ipl);
		hil = next;
	}
	if (wakeup)
		thread_wakeup((event_t)&hil_head);
}
