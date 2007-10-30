/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
/*
 * Copyright (c) 1992,7 NeXT Computer, Inc.
 *
 * Unix data structure initialization.
 *
 */

#include <mach/mach_types.h>

#include <vm/vm_kern.h>
#include <mach/vm_prot.h>

#include <sys/param.h>
#include <sys/buf_internal.h>
#include <sys/clist.h>
#include <sys/mbuf.h>
#include <sys/systm.h>
#include <sys/tty.h>
#include <sys/vnode.h>
#include <sys/sysctl.h>
#include <dev/ppc/cons.h>

extern vm_map_t mb_map;

extern u_long   tcp_sendspace;
extern u_long   tcp_recvspace;

void            bsd_bufferinit(void);
extern void     md_prepare_for_shutdown(int, int, char *);

int		bsd_mbuf_cluster_reserve(void);

/*
 * Declare these as initialized data so we can patch them.
 */

#ifdef	NBUF
int             max_nbuf_headers = NBUF;
int             niobuf = NBUF / 2;
int 		nbuf_hashelements = NBUF;
int 		nbuf = NBUF;
#else
int             max_nbuf_headers = 0;
int             niobuf = 0;
int 		nbuf_hashelements = 0;
int		nbuf = 0;
#endif

SYSCTL_INT (_kern, OID_AUTO, nbuf, CTLFLAG_RD, &nbuf, 0, "");
SYSCTL_INT (_kern, OID_AUTO, maxnbuf, CTLFLAG_RW, &max_nbuf_headers, 0, "");

__private_extern__ int customnbuf = 0;
int             srv = 0;	/* Flag indicates a server boot when set */
int             ncl = 0;

vm_map_t        buffer_map;
vm_map_t        bufferhdr_map;


extern void     bsd_startupearly(void);

void
bsd_startupearly(void)
{
	vm_offset_t     firstaddr;
	vm_size_t       size;
	kern_return_t   ret;

	/* clip the number of buf headers upto 16k */
	if (max_nbuf_headers == 0)
		max_nbuf_headers = atop(sane_size / 50);	/* Get 2% of ram, but no more than we can map */
	if ((customnbuf == 0) && (max_nbuf_headers > 16384))
		max_nbuf_headers = 16384;
	if (max_nbuf_headers < 256)
		max_nbuf_headers = 256;

	/* clip the number of hash elements  to 200000 */
	if ( (customnbuf == 0 ) && nbuf_hashelements == 0) {
		nbuf_hashelements = atop(sane_size / 50);
		if (nbuf_hashelements > 200000)
			nbuf_hashelements = 200000;
	} else
		nbuf_hashelements = max_nbuf_headers;

	if (niobuf == 0)
		niobuf = max_nbuf_headers;
	if (niobuf > 4096)
		niobuf = 4096;
	if (niobuf < 128)
		niobuf = 128;

	size = (max_nbuf_headers + niobuf) * sizeof(struct buf);
	size = round_page(size);

	ret = kmem_suballoc(kernel_map,
			    &firstaddr,
			    size,
			    FALSE,
			    VM_FLAGS_ANYWHERE,
			    &bufferhdr_map);

	if (ret != KERN_SUCCESS)
		panic("Failed to create bufferhdr_map");

	ret = kernel_memory_allocate(bufferhdr_map,
				     &firstaddr,
				     size,
				     0,
				     KMA_HERE | KMA_KOBJECT);

	if (ret != KERN_SUCCESS)
		panic("Failed to allocate bufferhdr_map");

	buf = (struct buf *) firstaddr;
	bzero(buf, size);

	{
		int             scale;

		nmbclusters = bsd_mbuf_cluster_reserve() / MCLBYTES;

		if ((scale = nmbclusters / NMBCLUSTERS) > 1) {
			tcp_sendspace *= scale;
			tcp_recvspace *= scale;

			if (tcp_sendspace > (32 * 1024))
				tcp_sendspace = 32 * 1024;
			if (tcp_recvspace > (32 * 1024))
				tcp_recvspace = 32 * 1024;
		}
	}

	/*
	 * Size vnodes based on memory 
	 * Number vnodes  is (memsize/64k) + 1024 
	 * This is the calculation that is used by launchd in tiger
	 * we are clipping the max based on 16G 
	 * ie ((16*1024*1024*1024)/(64 *1024)) + 1024 = 263168;
	 */
	desiredvnodes  = (sane_size/65536) + 1024;
	if (desiredvnodes > 263168)
		desiredvnodes = 263168;
}

void
bsd_bufferinit(void)
{
	kern_return_t   ret;

	cons.t_dev = makedev(12, 0);

	bsd_startupearly();

	ret = kmem_suballoc(kernel_map,
			    (vm_offset_t *) & mbutl,
			    (vm_size_t) (nmbclusters * MCLBYTES),
			    FALSE,
			    VM_FLAGS_ANYWHERE,
			    &mb_map);

	if (ret != KERN_SUCCESS)
		panic("Failed to allocate mb_map\n");

	/*
	 * Set up buffers, so they can be used to read disk labels.
	 */
	bufinit();
}

/*
 * this has been broken out into a separate routine that
 * can be called from the x86 early vm initialization to
 * determine how much lo memory to reserve on systems with
 * DMA hardware that can't fully address all of the physical
 * memory that is present.
 */
int
bsd_mbuf_cluster_reserve(void)
{
	if (sane_size > (64 * 1024 * 1024) || ncl) {

	        if ((nmbclusters = ncl) == 0) {
		        if ((nmbclusters = ((sane_size / 16)/MCLBYTES)) > 32768)
			        nmbclusters = 32768;
		}
	}

	return (nmbclusters * MCLBYTES);
}
