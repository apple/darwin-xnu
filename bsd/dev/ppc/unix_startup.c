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
 * Copyright (c) 1992,7 NeXT Computer, Inc.
 *
 * Unix data structure initialization.
 */

#include <mach/mach_types.h>

#include <vm/vm_kern.h>
#include <mach/vm_prot.h>

#include <sys/param.h>
#include <sys/buf.h>
#include <sys/clist.h>
#include <sys/mbuf.h>
#include <sys/systm.h>
#include <sys/tty.h>
#include <dev/ppc/cons.h>

extern vm_map_t	mb_map;

/*
 * Declare these as initialized data so we can patch them.
 */

#ifdef	NBUF
int		nbuf = NBUF;
int		niobuf = NBUF/2;
#else
int		nbuf = 0;
int		niobuf = 0;
#endif

int	srv = 0;          /* Flag indicates a server boot when set */
int	ncl = 0;

vm_map_t	bufferhdr_map;

void
bsd_startupearly()
{
	vm_offset_t		firstaddr;
	vm_size_t		size;
	kern_return_t	ret;

	if (nbuf == 0)
		nbuf = atop_64(sane_size / 100); /* Get 1% of ram, but no more than we can map */
	if (nbuf > 8192)
		nbuf = 8192;
	if (nbuf < 256)
		nbuf = 256;

	if (niobuf == 0)
		niobuf = nbuf;
	if (niobuf > 4096)
		niobuf = 4096;
	if (niobuf < 128)
		niobuf = 128;

	size = (nbuf + niobuf) * sizeof (struct buf);
	size = round_page_32(size);

	ret = kmem_suballoc(kernel_map,
			&firstaddr,
			size,
			FALSE,
			TRUE,
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

	buf = (struct buf * )firstaddr;
	bzero(buf,size);

	if ((sane_size > (64 * 1024 * 1024)) || ncl) {
		int scale;
		extern u_long tcp_sendspace;
		extern u_long tcp_recvspace;

		if ((nmbclusters = ncl) == 0) {
			if ((nmbclusters = ((sane_size / 16) / MCLBYTES)) > 16384)
				nmbclusters = 16384;
		}
		if ((scale = nmbclusters / NMBCLUSTERS) > 1) {
			tcp_sendspace *= scale;
			tcp_recvspace *= scale;

			if (tcp_sendspace > (32 * 1024))
				tcp_sendspace = 32 * 1024;
			if (tcp_recvspace > (32 * 1024))
				tcp_recvspace = 32 * 1024;
		}
	}
}

void
bsd_bufferinit()
{
    kern_return_t	ret;

    cons.t_dev = makedev(12, 0);

	bsd_startupearly();

   	ret = kmem_suballoc(kernel_map,
			&mbutl,
			(vm_size_t) (nmbclusters * MCLBYTES),
			FALSE,
			TRUE,
			&mb_map);

	if (ret != KERN_SUCCESS) 
		panic("Failed to allocate mb_map\n");
	
    /*
     * Set up buffers, so they can be used to read disk labels.
     */
    bufinit();
}

void
md_prepare_for_shutdown(int paniced, int howto, char * command)
{
	extern void IOSystemShutdownNotification();

    /*
     * Temporary hack to notify the power management root domain
     * that the system will shut down.
     */
    IOSystemShutdownNotification();
}
