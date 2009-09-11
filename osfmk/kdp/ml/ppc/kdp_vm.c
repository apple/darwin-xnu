/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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
#include <mach/mach_types.h>
#include <mach/vm_attributes.h>
#include <mach/vm_param.h>

#include <vm/pmap.h>
 
#include <ppc/proc_reg.h>
#include <ppc/machparam.h>
#include <ppc/mem.h>
#include <ppc/pmap.h>
#include <ppc/mappings.h> 
#include <ppc/cpu_data.h>
#include <ppc/misc_protos.h>

#include <mach/thread_status.h>
#include <mach-o/loader.h>
#include <mach/vm_region.h>
#include <mach/vm_statistics.h>

#include <vm/vm_kern.h>
#include <vm/vm_object.h>
#include <vm/vm_protos.h>
#include <kdp/kdp_core.h>
#include <kdp/kdp_udp.h>
#include <kdp/kdp_internal.h>

#include <ppc/misc_protos.h>
#include <mach/vm_map.h>


pmap_t kdp_pmap;
boolean_t kdp_trans_off;
boolean_t kdp_read_io;

extern vm_offset_t sectTEXTB, sectDATAB, sectLINKB, sectPRELINKB;
extern unsigned long sectSizeTEXT, sectSizeDATA, sectSizeLINK, sectSizePRELINK;

static addr64_t	kdp_vtophys(pmap_t pmap, addr64_t va);
int             kern_dump(void);

typedef struct {
  int	flavor;			/* the number for this flavor */
  mach_msg_type_number_t	count;	/* count of ints in this flavor */
} mythread_state_flavor_t;

static mythread_state_flavor_t thread_flavor_array[] = {
  {PPC_THREAD_STATE , PPC_THREAD_STATE_COUNT},
};

static int kdp_mynum_flavors = 1;
static int MAX_TSTATE_FLAVORS = 1;

typedef struct {
  vm_offset_t header; 
  int  hoffset;
  mythread_state_flavor_t *flavors;
  int tstate_size;
} tir_t;

char command_buffer[512];

/*
 *
 */
static addr64_t
kdp_vtophys(
	pmap_t pmap,
	addr64_t va)
{
	addr64_t    pa;
	ppnum_t pp;

	pp = pmap_find_phys(pmap, va);				/* Get the page number */
	if(!pp) return 0;							/* Just return if no translation */
	
	pa = ((addr64_t)pp << 12) | (va & 0x0000000000000FFFULL);	/* Shove in the page offset */
	return(pa);
}
/* Verify that src is valid, and physically copy len bytes from src to
 * dst, translating if necessary. If translation is enabled
 * (kdp_trans_off is 0), a non-zero kdp_pmap specifies the pmap to use
 * when translating src.
 */

mach_vm_size_t
kdp_machine_vm_read( mach_vm_address_t src, caddr_t dst, mach_vm_size_t len)
{
	addr64_t cur_virt_src, cur_virt_dst;
	addr64_t cur_phys_src, cur_phys_dst;
	unsigned resid, cnt;
	unsigned int dummy;
	pmap_t pmap;

#ifdef KDP_VM_READ_DEBUG
    kprintf("kdp_machine_vm_read1: src %llx dst %llx len %x - %08X %08X\n", src, dst, len, ((unsigned long *)src)[0], ((unsigned long *)src)[1]);
#endif

	cur_virt_src = (addr64_t)src;
	cur_virt_dst = (addr64_t)(intptr_t)dst;
	
	if (kdp_trans_off) {
		resid = len;	/* Get the length to copy */

		while (resid != 0) {

			if((cur_phys_dst = kdp_vtophys(kernel_pmap, cur_virt_dst)) == 0)
				goto exit;

			if(kdp_read_io == 0)
				if(!mapping_phys_lookup((ppnum_t)(cur_virt_src >> 12), &dummy)) return 0;	/* Can't read where there's not any memory */
		
			cnt = 4096 - (cur_virt_src & 0xFFF);	/* Get length left on page */
			if (cnt > (4096 - (cur_virt_dst & 0xFFF)))
				cnt = 4096 - (cur_virt_dst & 0xFFF);
		
			if (cnt > resid)  cnt = resid;

			bcopy_phys(cur_virt_src, cur_phys_dst, cnt);		/* Copy stuff over */

			cur_virt_src += cnt;
			cur_virt_dst += cnt;
			resid -= cnt;
		}
		
	} else {

		resid = len;

		if(kdp_pmap) pmap = kdp_pmap;				/* If special pmap, use it */
		else pmap = kernel_pmap;					/* otherwise, use kernel's */

		while (resid != 0) {   
/* Always translate the destination using the kernel_pmap. */
			if((cur_phys_dst = kdp_vtophys(kernel_pmap, cur_virt_dst)) == 0)
				goto exit;

			if((cur_phys_src = kdp_vtophys(pmap, cur_virt_src)) == 0)
				goto exit;

			if(kdp_read_io == 0)
				if(!mapping_phys_lookup((ppnum_t)(cur_phys_src >> 12), &dummy)) goto exit;	/* Can't read where there's not any memory */

			cnt = 4096 - (cur_virt_src & 0xFFF);	/* Get length left on page */
			if (cnt > (4096 - (cur_virt_dst & 0xFFF)))
				cnt = 4096 - (cur_virt_dst & 0xFFF);

			if (cnt > resid) cnt = resid;

#ifdef KDP_VM_READ_DEBUG
				kprintf("kdp_machine_vm_read2: pmap %08X, virt %016LLX, phys %016LLX\n", 
					pmap, cur_virt_src, cur_phys_src);
#endif

			bcopy_phys(cur_phys_src, cur_phys_dst, cnt);		/* Copy stuff over */
			
			cur_virt_src +=cnt;
			cur_virt_dst +=cnt;
			resid -= cnt;
		}
	}
exit:
#ifdef KDP_VM_READ_DEBUG
	kprintf("kdp_machine_vm_read: ret %08X\n", len-resid);
#endif
        return (len - resid);
}

mach_vm_size_t
kdp_machine_phys_read(kdp_readphysmem64_req_t *rq __unused, caddr_t dst __unused, uint16_t lcpu __unused)
{
    return 0; /* unimplemented */
}

/*
 * 
 */
mach_vm_size_t
kdp_machine_vm_write( caddr_t src, mach_vm_address_t dst, mach_vm_size_t len)
{
	addr64_t cur_virt_src, cur_virt_dst;
	addr64_t cur_phys_src, cur_phys_dst;
	unsigned resid, cnt, cnt_src, cnt_dst;

#ifdef KDP_VM_WRITE_DEBUG
	printf("kdp_vm_write: src %x dst %x len %x - %08X %08X\n", src, dst, len, ((unsigned long *)src)[0], ((unsigned long *)src)[1]);
#endif

	cur_virt_src = (addr64_t)(intptr_t)src;
	cur_virt_dst = (addr64_t)dst;

	resid = len;

	while (resid != 0) {
		if ((cur_phys_dst = kdp_vtophys(kernel_pmap, cur_virt_dst)) == 0) 
			goto exit;

		if ((cur_phys_src = kdp_vtophys(kernel_pmap, cur_virt_src)) == 0) 
			goto exit;

		cnt_src = ((cur_phys_src + NBPG) & (-NBPG)) - cur_phys_src;
		cnt_dst = ((cur_phys_dst + NBPG) & (-NBPG)) - cur_phys_dst;

		if (cnt_src > cnt_dst)
			cnt = cnt_dst;
		else
			cnt = cnt_src;
		if (cnt > resid) 
			cnt = resid;

		bcopy_phys(cur_phys_src, cur_phys_dst, cnt);		/* Copy stuff over */
		sync_cache64(cur_phys_dst, cnt);					/* Sync caches */

		cur_virt_src +=cnt;
		cur_virt_dst +=cnt;
		resid -= cnt;
	}
exit:
	return (len - resid);
}

mach_vm_size_t
kdp_machine_phys_write(kdp_writephysmem64_req_t *rq __unused, caddr_t src __unused,
		       uint16_t lcpu __unused)
{
    return 0; /* unimplemented */
}

static void
kern_collectth_state(thread_t thread, tir_t *t)
{
  vm_offset_t	header;
  int  hoffset, i ;
  mythread_state_flavor_t *flavors;
  struct thread_command	*tc;
  /*
   *	Fill in thread command structure.
   */
  header = t->header;
  hoffset = t->hoffset;
  flavors = t->flavors;
	
  tc = (struct thread_command *) (header + hoffset);
  tc->cmd = LC_THREAD;
  tc->cmdsize = sizeof(struct thread_command)
    + t->tstate_size;
  hoffset += sizeof(struct thread_command);
  /*
   * Follow with a struct thread_state_flavor and
   * the appropriate thread state struct for each
   * thread state flavor.
   */
  for (i = 0; i < kdp_mynum_flavors; i++) {
    *(mythread_state_flavor_t *)(header+hoffset) =
      flavors[i];
    hoffset += sizeof(mythread_state_flavor_t);

    if (machine_thread_get_kern_state(thread, flavors[i].flavor,
			     (thread_state_t) (header+hoffset),
				      &flavors[i].count) != KERN_SUCCESS)
      printf ("Failure in machine_thread_get_kern_state()\n");
    hoffset += flavors[i].count*sizeof(int);
  }

  t->hoffset = hoffset;
}

int
kdp_dump_trap(
	      int type,
	      __unused struct savearea *regs)
{
  printf ("An unexpected trap (type %d) occurred during the kernel dump, terminating.\n", type);
  kdp_send_crashdump_pkt(KDP_EOF, NULL, 0, ((void *) 0));
  abort_panic_transfer();
  kdp_flag &= ~KDP_PANIC_DUMP_ENABLED;
  kdp_flag &= ~PANIC_CORE_ON_NMI;
  kdp_flag &= ~PANIC_LOG_DUMP;

  kdp_reset();

  kdp_raise_exception(EXC_BAD_ACCESS, 0, 0, kdp.saved_state);
  return( 0 );
}

/*
 * Kernel dump (limited to currently executing 32 bit mach_kernel only)
 */
int
kern_dump(void)
{
  int error = 0;
  vm_map_t	map;
  unsigned int	thread_count, segment_count;
  unsigned int	command_size = 0, header_size = 0, tstate_size = 0;
  unsigned int	hoffset = 0, foffset = 0, nfoffset = 0,  vmoffset = 0;
  unsigned int  max_header_size = 0;
  vm_offset_t	header;
  struct mach_header	*mh;
  struct segment_command	*sc;
  vm_size_t	size;
  vm_prot_t	prot = 0;
  vm_prot_t	maxprot = 0;
  vm_inherit_t	inherit = 0;
  int		error1 = 0;
  mythread_state_flavor_t flavors[MAX_TSTATE_FLAVORS];
  vm_size_t	nflavors;
  vm_size_t	i;
  uint32_t nesting_depth = 0;
  kern_return_t	kret = 0;
  struct vm_region_submap_info_64 vbr;
  mach_msg_type_number_t vbrcount  = 0;
  tir_t tir1;

  int panic_error = 0;
  unsigned int txstart = 0;
  unsigned int mach_section_count = 4;
  unsigned int num_sects_txed = 0;

  map = kernel_map;

  thread_count = 1;
  segment_count = get_vmmap_entries(map); 
  
  printf("Kernel map has %d entries\n", segment_count);

  nflavors = kdp_mynum_flavors;
  bcopy((char *)thread_flavor_array,(char *) flavors,sizeof(thread_flavor_array));

  for (i = 0; i < nflavors; i++)
    tstate_size += sizeof(mythread_state_flavor_t) +
      (flavors[i].count * sizeof(int));

  command_size = (segment_count + mach_section_count) *
    sizeof(struct segment_command) +
    thread_count*sizeof(struct thread_command) +
    tstate_size*thread_count;

  header_size = command_size + sizeof(struct mach_header);
  header = (vm_offset_t) command_buffer;
	
  /*
   *	Set up Mach-O header for currently executing 32 bit kernel.
   */
  printf ("Generated Mach-O header size was %d\n", header_size);

  mh = (struct mach_header *) header;
  mh->magic = MH_MAGIC;
  mh->cputype = cpu_type();
  mh->cpusubtype = cpu_subtype();	/* XXX incorrect; should match kernel */
  mh->filetype = MH_CORE;
  mh->ncmds = segment_count + thread_count + mach_section_count;
  mh->sizeofcmds = command_size;
  mh->flags = 0;

  hoffset = sizeof(struct mach_header);	/* offset into header */
  foffset = round_page_32(header_size); /* offset into file */
  /* Padding.. */
  if ((foffset - header_size) < (4*sizeof(struct segment_command))) {
      /* Hack */
      foffset += ((4*sizeof(struct segment_command)) - (foffset-header_size)); 
    }

  max_header_size = foffset;

  vmoffset = VM_MIN_ADDRESS;		/* offset into VM */

  /* Transmit the Mach-O MH_CORE header, and seek forward past the 
   * area reserved for the segment and thread commands 
   * to begin data transmission 
   */

   if ((panic_error = kdp_send_crashdump_pkt(KDP_SEEK, NULL, sizeof(nfoffset) , &nfoffset)) < 0) { 
     printf ("kdp_send_crashdump_pkt failed with error %d\n", panic_error); 
     return -1; 
   } 

   if ((panic_error = kdp_send_crashdump_data(KDP_DATA, NULL, sizeof(struct mach_header), (caddr_t) mh) < 0)) {
     printf ("kdp_send_crashdump_data failed with error %d\n", panic_error);
     return -1 ;
   }

   if ((panic_error = kdp_send_crashdump_pkt(KDP_SEEK, NULL, sizeof(foffset) , &foffset) < 0)) {
     printf ("kdp_send_crashdump_pkt failed with error %d\n", panic_error);
     return (-1);
   }
  printf ("Transmitting kernel state, please wait: ");

  while ((segment_count > 0) || (kret == KERN_SUCCESS)){
    /* Check if we've transmitted all the kernel sections */
    if (num_sects_txed == mach_section_count) {
      
    while (1) {

    /*
     *	Get region information for next region.
     */

      vbrcount = VM_REGION_SUBMAP_INFO_COUNT_64;
      if((kret = vm_region_recurse_64(map, 
				      &vmoffset, &size, &nesting_depth, 
				      (vm_region_recurse_info_t)&vbr,
				      &vbrcount)) != KERN_SUCCESS) {
	break;
      }

      if(vbr.is_submap) {
	nesting_depth++;
	continue;
      } else {
	break;
      }
    }

    if(kret != KERN_SUCCESS)
      break;

    prot = vbr.protection;
    maxprot = vbr.max_protection;
    inherit = vbr.inheritance;
    }
    else
      {
	switch (num_sects_txed) {
	case 0:
	  {
	    /* Transmit the kernel text section */
	    vmoffset = sectTEXTB;
	    size = sectSizeTEXT;
	  }
	  break;
        case 1:
	  {
	    vmoffset = sectDATAB;
	    size = sectSizeDATA;
	  }
	  break;
	case 2:
	  {
	    vmoffset = sectPRELINKB;
	    size = sectSizePRELINK;
	  }
	  break;
	case 3:
	  {
	    vmoffset = sectLINKB;
	    size = sectSizeLINK;
	  }
	  break;
	  /* TODO the lowmem vector area may be useful, but its transmission is
	   * disabled for now. The traceback table area should be transmitted 
	   * as well - that's indirected from 0x5080.
	   */
	}
	num_sects_txed++;
      }
    /*
     *	Fill in segment command structure.
     */
    
    if (hoffset > max_header_size)
      break;
    sc = (struct segment_command *) (header);
    sc->cmd = LC_SEGMENT;
    sc->cmdsize = sizeof(struct segment_command);
    sc->segname[0] = 0;
    sc->vmaddr = vmoffset;
    sc->vmsize = size;
    sc->fileoff = foffset;
    sc->filesize = size;
    sc->maxprot = maxprot;
    sc->initprot = prot;
    sc->nsects = 0;

    if ((panic_error = kdp_send_crashdump_pkt(KDP_SEEK, NULL, sizeof(hoffset) , &hoffset)) < 0) { 
	printf ("kdp_send_crashdump_pkt failed with error %d\n", panic_error); 
	return -1; 
      } 
    
    if ((panic_error = kdp_send_crashdump_data(KDP_DATA, NULL, sizeof(struct segment_command) , (caddr_t) sc)) < 0) {
	printf ("kdp_send_crashdump_data failed with error %d\n", panic_error);
	return -1 ;
      }

    /* Do not transmit memory tagged VM_MEMORY_IOKIT - instead, seek past that
     * region on the server - this creates a hole in the file  
     */

    if ((vbr.user_tag != VM_MEMORY_IOKIT)) {
      
      if ((panic_error = kdp_send_crashdump_pkt(KDP_SEEK, NULL, sizeof(foffset) , &foffset)) < 0) {
	  printf ("kdp_send_crashdump_pkt failed with error %d\n", panic_error);
	  return (-1);
	}

      txstart = vmoffset;

      if ((panic_error = kdp_send_crashdump_data(KDP_DATA, NULL, size, (caddr_t) txstart)) < 0)	{
	  printf ("kdp_send_crashdump_data failed with error %d\n", panic_error);
	  return -1 ;
	}
    }

    hoffset += sizeof(struct segment_command);
    foffset += size;
    vmoffset += size;
    segment_count--;
  }
  tir1.header = header;
  tir1.hoffset = 0;
  tir1.flavors = flavors;
  tir1.tstate_size = tstate_size;

  /* Now send out the LC_THREAD load command, with the thread information
   * for the current activation.
   * Note that the corefile can contain LC_SEGMENT commands with file offsets
   * that point past the edge of the corefile, in the event that the last N
   * VM regions were all I/O mapped or otherwise non-transferable memory, 
   * not followed by a normal VM region; i.e. there will be no hole that 
   * reaches to the end of the core file.
   */
  kern_collectth_state (current_thread(), &tir1);

  if ((panic_error = kdp_send_crashdump_pkt(KDP_SEEK, NULL, sizeof(hoffset) , &hoffset)) < 0) { 
      printf ("kdp_send_crashdump_pkt failed with error %d\n", panic_error); 
      return -1; 
    } 
  
    if ((panic_error = kdp_send_crashdump_data(KDP_DATA, NULL, tir1.hoffset , (caddr_t) header)) < 0) {
	printf ("kdp_send_crashdump_data failed with error %d\n", panic_error);
	return -1 ;
      }
    
    /* last packet */
    if ((panic_error = kdp_send_crashdump_pkt(KDP_EOF, NULL, 0, ((void *) 0))) < 0)
      {
	printf ("kdp_send_crashdump_pkt failed with error %d\n", panic_error);
	return (-1) ;
      }
    
    if (error == 0)
      error = error1;
    return (error);
}
