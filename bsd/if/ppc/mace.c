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
 * MACE Device-dependent code (some still lives in if_en.c):
 *
 * MACE Multicast Address scheme -
 *  Compute Enet CRC for each Mcast address; take high 6 bits of 32-bit
 *   crc, giving a "bit index" into a 64-bit register.  On packet receipt,
 *   if corresponding bit is set, accept packet.
 *  We keep track of requests in a per-hash-value table (16-bit counters
 *   should be sufficient).  Since we're hashing, we only care about the
 *   hash value of each address.
 *
 * Apple Confidential
 *
 * (C) COPYRIGHT Apple Computer, Inc., 1994-1997
 * All Rights Reserved
 *
 * Justin C. Walker
 */
#include <machdep/ppc/dbdma.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/etherdefs.h>
#include	<netinet/if_ether.h>
#include	<sys/sockio.h>
#include	<netinet/in_var.h>
#include	<netinet/in.h>
#include <sys/mbuf.h>
#include <mach/mach_types.h>
#include <ppc/powermac.h>
#include <ppc/interrupts.h>
#include <ppc/proc_reg.h>
#include <libkern/libkern.h>
#include "if_en.h"
#include "mace.h"

extern mace_t mace;

#define ENET_CRCPOLY 0x04c11db7

/* Real fast bit-reversal algorithm, 6-bit values */
int reverse6[] = 
{	0x0,0x20,0x10,0x30,0x8,0x28,0x18,0x38,
	0x4,0x24,0x14,0x34,0xc,0x2c,0x1c,0x3c,
	0x2,0x22,0x12,0x32,0xa,0x2a,0x1a,0x3a,
	0x6,0x26,0x16,0x36,0xe,0x2e,0x1e,0x3e,
	0x1,0x21,0x11,0x31,0x9,0x29,0x19,0x39,
	0x5,0x25,0x15,0x35,0xd,0x2d,0x1d,0x3d,
	0x3,0x23,0x13,0x33,0xb,0x2b,0x1b,0x3b,
	0x7,0x27,0x17,0x37,0xf,0x2f,0x1f,0x3f
};

unsigned int crc416(current, nxtval)
register unsigned int current;
register unsigned short nxtval;
{	register unsigned int counter;
	register int highCRCBitSet, lowDataBitSet;

	/* Swap bytes */
	nxtval = ((nxtval & 0x00FF) << 8) | (nxtval >> 8);

	/* Compute bit-by-bit */
	for (counter = 0; counter != 16; ++counter)
	{	/* is high CRC bit set? */
		if ((current & 0x80000000) == NULL)
			highCRCBitSet = 0;
		else
			highCRCBitSet = 1;
		
		current = current << 1;
	
		if ((nxtval & 0x0001) == NULL)
			lowDataBitSet = 0;
		else
			lowDataBitSet = 1;

		nxtval = nxtval >> 1;
	
		/* do the XOR */
		if (highCRCBitSet ^ lowDataBitSet)
			current = current ^ ENET_CRCPOLY;
	}
	return current;
}

unsigned int mace_crc(unsigned short *address)
{	register unsigned int newcrc;

	newcrc = crc416(0xffffffff, *address);	/* address bits 47 - 32 */
	newcrc = crc416(newcrc, address[1]);	/* address bits 31 - 16 */
	newcrc = crc416(newcrc, address[2]);	/* address bits 15 - 0 */

	return(newcrc);
}

/*
 * Add requested mcast addr to Mace's filter.  Assume that the first
 *  address in the arpcom ac_multiaddrs list is the one we're interested in.
 */
int
mace_addmulti(register struct ifreq *ifr, register struct arpcom *ar)
{	register unsigned char *addr;
	unsigned int crc;
	unsigned char mask;

	addr = ar->ac_multiaddrs->enm_addrlo;

	crc = mace_crc((unsigned short *)addr)&0x3f; /* Big-endian alert! */
	crc = reverse6[crc];	/* Hyperfast bit-reversing algorithm */
	if (mace.multi_use[crc]++)
		return(0);		/* This bit is already set */
	mask = crc % 8;
	mask = (unsigned char)1 << mask;
	mace.multi_mask[crc/8] |= mask;
	return(1);
}

int
mace_delmulti(register struct ifreq *ifr, register struct arpcom *ar,
	      struct ether_addr * enaddr)
{	register unsigned char *addr;
	unsigned int crc;
	unsigned char mask;

	addr = (char *)enaddr; /* XXX assumes addrlo == addrhi */

	/* Now, delete the address from the filter copy, as indicated */
	crc = mace_crc((unsigned short *)addr)&0x3f; /* Big-endian alert! */
	crc = reverse6[crc];	/* Hyperfast bit-reversing algorithm */
	if (mace.multi_use[crc] == 0)
		return(EINVAL);		/* That bit wasn't in use! */

	if (--mace.multi_use[crc])
		return(0);		/* That bit is still in use */

	mask = crc % 8;
	mask = ((unsigned char)1 << mask) ^ 0xff; /* To turn off bit */
	mace.multi_mask[crc/8] &= mask;
	return(1);
}

/*
 * Sync the adapter with the software copy of the multicast mask
 *  (logical address filter).
 * If we want all m-cast addresses, we just blast 1's into the filter.
 *  When we reverse this, we can use the current state of the (software)
 *  filter, which should have been kept up to date.
 */
void
mace_sync_mcast(register struct ifnet * ifp)
{	register unsigned long temp, temp1;
	register int	  i;
	register char	 *p;
	register struct mace_board *ereg = mace.ereg;

	temp = ereg->maccc;

	/*
	 * Have to deal with early rev of chip for updating LAF
	 * Don't know if any MacOSX systems still run this rev.
	 */
	if (mace.chip_id == MACERevA2)
	{	/* First, turn off receiver */
		temp1 = temp&~MACCC_ENRCV;
		ereg->maccc = temp1;
		eieio();

		/* Then, check FIFO - frame being received will complete */
		temp1 = ereg->fifofc;

		mace.ereg->iac = IAC_LOGADDR;
		eieio();
	} else
	{	ereg->iac = IAC_ADDRCHG|IAC_LOGADDR;
		eieio();

		while (temp1 = ereg->iac)
		{	eieio();
			if ((temp1&IAC_ADDRCHG) == 0)
				break;
		}
	}

	if (ifp->if_flags & IFF_ALLMULTI)	/* Then want ALL m-cast pkts */
	{	/* set mask to all 1's */
		for (i=0;i<8;i++)
		{	ereg->ladrf = 0xff;
			eieio();
		}
	} else
	{
		/* Assuming everything is big-endian */
		for (i=0, p = &mace.multi_mask[0];i<8;i++)
		{	ereg->ladrf = *p++;
			eieio();
		}
	}

	ereg->maccc = temp;		/* Reset config ctrlr */
	eieio();

}

void
mace_sync_promisc(register struct ifnet *ifp)
{
	register u_long o_maccc, n_maccc;
	register struct mace_board *ereg = mace.ereg;

	/*
	 * Save current state and disable receive.
	 */
	o_maccc = ereg->maccc;
	n_maccc = o_maccc & ~MACCC_ENRCV;
	ereg->maccc = n_maccc;
	eieio();

	/*
	 * Calculate new desired state
	 */
	if (ifp->if_flags & IFF_PROMISC) {
		/* set PROMISC bit */
		o_maccc |= MACCC_PROM;
	} else {
		/* clear PROMISC bit */
		o_maccc &= ~MACCC_PROM;
	}

	/*
	 * Note that the "old" mode includes the new promiscuous state now.
	 */
	ereg->maccc = o_maccc;
	eieio();
}
