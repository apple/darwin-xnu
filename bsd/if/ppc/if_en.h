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
 * MacOSX Mace driver
 * Defines and device state
 * Dieter Siegmund (dieter@next.com) Thu Feb 27 18:25:33 PST 1997
 * - ripped off code from MK/LINUX
 */

#define PG_SIZE		0x1000UL
#define PG_MASK		(PG_SIZE - 1UL)

#define ETHERMTU		1500
#define	ETHER_RX_NUM_DBDMA_BUFS	32
#define	ETHERNET_BUF_SIZE	(ETHERMTU + 36)
#define ETHER_MIN_PACKET	64
#define TX_NUM_DBDMA		6

#define	DBDMA_ETHERNET_EOP	0x40

typedef struct mace_s {
    struct arpcom 		en_arpcom;
    struct mace_board * 	ereg;	/* ethernet register set address */
    unsigned char		macaddr[NUM_EN_ADDR_BYTES]; /* mac address */
    int				chip_id;
    dbdma_command_t		*rv_dma;
    dbdma_command_t		*tx_dma;
    unsigned char		*rv_dma_area;
    unsigned char		*tx_dma_area;
    unsigned char		multi_mask[8]; /* Multicast mask */
    unsigned char		multi_use[64]; /* Per-mask-bit use count */
    int				rv_tail;
    int				rv_head;
    int				tx_busy;
    int				txintr;
    int				rxintr;
    int				txwatchdog;
    int				ready;
    int				promisc;	/* IFF_PROMISC state */
} mace_t;

