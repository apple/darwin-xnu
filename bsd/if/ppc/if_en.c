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
 * Copyright (c) 1997 Apple Computer, Inc.
 *
 * ethernet driver for mace on-board ethernet
 *
 * HISTORY
 *
 * Dieter Siegmund (dieter@next.com) Thu Feb 27 18:25:33 PST 1997
 * - ripped off code from MK/LINUX, turned it into a polled-mode
 *   driver for the PCI (8500) class machines
 *
 * Dieter Siegmund (dieter@next.com) Fri Mar 21 12:41:29 PST 1997
 * - reworked to support a BSD-style interface, and to support kdb polled
 *   interface and interrupt-driven interface concurrently
 *
 * Justin Walker (justin@apple.com) Tue May 20 10:29:29 PDT 1997
 * - Added multicast support
 *
 * Dieter Siegmund (dieter@next.com) Thu May 29 15:02:29 PDT 1997
 * - fixed problem with sending arp packets for ip address 0.0.0.0
 * - use kdp_register_send_receive() instead of defining 
 *   en_send_pkt/en_recv_pkt routines to avoid name space 
 *   collisions with IOEthernetDebugger and allow these routines to be
 *   overridden by a driverkit-style driver
 *
 * Dieter Siegmund (dieter@apple.com) Tue Jun 24 18:29:15 PDT 1997
 * - don't let the adapter auto-strip 802.3 receive frames, it messes
 *   up the frame size logic
 *
 * Dieter Siegmund (dieter@apple.com) Tue Aug  5 16:24:52 PDT 1997
 * - handle multicast address deletion correctly
 */
#ifdef MACE_DEBUG
/*
 * Caveat: MACE_DEBUG delimits some code that is getting kind of
 *         stale. Before blindly turning on MACE_DEBUG for your
 *         testing, take a look at the code enabled by it to check
 *         that it is reasonably sane.
 */
#endif

#include <machdep/ppc/dbdma.h>
#include <kern/kdp_en_debugger.h>

#define RECEIVE_INT	DBDMA_INT_ALWAYS

#include <sys/types.h>
#include <sys/systm.h>
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
#include <kern/thread_call.h>
#include "if_en.h"
#include "mace.h"

extern int kdp_flag;

#if NBPFILTER > 0
#include <net/bpf.h>
#endif

static void polled_send_pkt(char * data, int len);
static void polled_receive_pkt(char *data, int *len, int timeout_ms);
void mace_dbdma_rx_intr(int unit, void *, void *);
void mace_dbdma_tx_intr(int, void *, void *);
void mace_pci_intr(int, void *);
void mace_service_queue(struct ifnet * ifp);

#ifdef MACE_DEBUG
static int mace_watchdog();
#endif

static __inline__ vm_offset_t
KVTOPHYS(vm_offset_t v)
{
    return (v);
}

typedef int (*funcptr)(char *, int, void *);

#ifdef MACE_DEBUG
static int
macAddrsEqual(unsigned char * one, unsigned char * two)
{
    int i;

    for (i = 0; i < NUM_EN_ADDR_BYTES; i++)
	if (*one++ != *two++)
	    return 0;
    return 1;
}
#endif

static __inline__ int
isprint(unsigned char c)
{
    return (c >= 0x20 && c <= 0x7e);
}

static void
printEtherHeader(enet_addr_t * dh, enet_addr_t * sh, u_short etype)
{
    u_char * dhost = dh->ether_addr_octet; 
    u_char * shost = sh->ether_addr_octet;

    printf("Dst: %x:%x:%x:%x:%x:%x Src: %x:%x:%x:%x:%x:%x Type: 0x%x\n", 
	    dhost[0], dhost[1], dhost[2], dhost[3], dhost[4], dhost[5],
	    shost[0], shost[1], shost[2], shost[3], shost[4], shost[5],
	    etype);
}

static void
printData(u_char * data_p, int n_bytes)
{
#define CHARS_PER_LINE 	16
    char		line_buf[CHARS_PER_LINE + 1];
    int			line_pos;
    int			offset;

    for (line_pos = 0, offset = 0; offset < n_bytes; offset++, data_p++) {
	if (line_pos == 0) {
	    printf("%04d ", offset);
	}

	line_buf[line_pos] = isprint(*data_p) ? *data_p : '.';
	printf(" %02x", *data_p);
	line_pos++;
	if (line_pos == CHARS_PER_LINE) {
	    line_buf[CHARS_PER_LINE] = '\0';
	    printf("  %s\n", line_buf);
	    line_pos = 0;
	}
    }
    if (line_pos) { /* need to finish up the line */
	for (; line_pos < CHARS_PER_LINE; line_pos++) {
	    printf("   ");
	    line_buf[line_pos] = ' ';
	}
	line_buf[CHARS_PER_LINE] = '\0';
	printf("  %s\n", line_buf);
    }
}

static void
printEtherPacket(enet_addr_t * dhost, enet_addr_t * shost, u_short type, 
		 u_char * data_p, int n_bytes)
{
    printEtherHeader(dhost, shost, type);
    printData(data_p, n_bytes);
}

void
printContiguousEtherPacket(u_char * data_p, int n_bytes)
{
    printEtherPacket((enet_addr_t *)data_p, 
		     (enet_addr_t *)(data_p + NUM_EN_ADDR_BYTES), 
		     *((u_short *)(data_p + (NUM_EN_ADDR_BYTES * 2))),
		     data_p, n_bytes);
}

mace_t	mace;

#define MACE_DMA_AREA_SIZE (ETHER_RX_NUM_DBDMA_BUFS * ETHERNET_BUF_SIZE + PG_SIZE)
static unsigned long mace_rx_dma_area[(MACE_DMA_AREA_SIZE + sizeof(long))/sizeof(long)];

static unsigned long mace_tx_dma_area[(ETHERNET_BUF_SIZE + PG_SIZE + sizeof(long))/sizeof(long)];

/*
 * mace_get_hwid
 *
 *	This function computes the Ethernet Hardware address
 *	from PROM. (Its best not to ask how this is done.)
 */

unsigned char
mace_swapbits(unsigned char bits)
{
	unsigned char	mask = 0x1, i, newbits = 0;

	for (i = 0x80; i; mask <<= 1, i >>=1) {
		if (bits & mask)
			newbits |= i;
	}

	return newbits;
}
	
void
mace_get_hwid(unsigned char *hwid_addr, mace_t * m)
{
	int		i;

	for (i = 0; i < NUM_EN_ADDR_BYTES; i++, hwid_addr += 16) {
	    m->macaddr[i] = mace_swapbits(*hwid_addr);
	}
}

/*
 * mace_reset
 *
 * Reset the board..
 */

void
mace_reset()
{
    dbdma_reset(DBDMA_ETHERNET_RV);
    dbdma_reset(DBDMA_ETHERNET_TX);
}


/*
 * mace_geteh:
 *
 *	This function gets the ethernet address (array of 6 unsigned
 *	bytes) from the MACE board registers.
 *
 */

void
mace_geteh(char *ep)
{
    int	i;
    unsigned char ep_temp;

    mace.ereg->iac = IAC_PHYADDR; eieio();
	
    for (i = 0; i < ETHER_ADD_SIZE; i++) {
	ep_temp = mace.ereg->padr; eieio();
	*ep++ = ep_temp;
    }
}

/*
 * mace_seteh:
 *
 *	This function sets the ethernet address (array of 6 unsigned
 *	bytes) on the MACE board. 
 */

static void
mace_seteh(char *ep)
{
    int	i;
    unsigned char	status;

    if (mace.chip_id != MACE_REVISION_A2) {
	mace.ereg->iac = IAC_ADDRCHG|IAC_PHYADDR; eieio();

	while ((status = mace.ereg->iac)) {
	    if ((status & IAC_ADDRCHG) == 0) {
		eieio();
		break;
	    }
	    eieio();
	}
    }
    else {
	/* start to load the address.. */
	mace.ereg->iac = IAC_PHYADDR; eieio();
    }

    for (i = 0; i < NUM_EN_ADDR_BYTES; i++) {
	mace.ereg->padr = *(ep+i); eieio();
    }
    return;
}

/*
 * mace_setup_dbdma
 *
 * Setup various dbdma pointers.
 */

void
mace_setup_dbdma()
{
    mace_t * 		m = &mace;
    int			i;
    dbdma_command_t *	d;
    vm_offset_t		address;
    dbdma_regmap_t *	regmap;

#define ALIGN_MASK	0xfffffffcUL
    if (m->rv_dma_area == 0) {
	m->rv_dma_area = (unsigned char *)
	    ((((unsigned long)mace_rx_dma_area) + 3) & ALIGN_MASK);
	m->rv_dma = dbdma_alloc(ETHER_RX_NUM_DBDMA_BUFS + 2);
	m->tx_dma = dbdma_alloc(TX_NUM_DBDMA);
	m->tx_dma_area = (unsigned char *)
	    ((((unsigned long)mace_tx_dma_area) + 3) & ALIGN_MASK);
    }

    /* set up a ring of buffers */
    d = m->rv_dma;
    for (i = 0; i < ETHER_RX_NUM_DBDMA_BUFS; i++, d++) {
	address = (vm_offset_t) KVTOPHYS((vm_offset_t)&m->rv_dma_area[i*ETHERNET_BUF_SIZE]);
	DBDMA_BUILD(d, DBDMA_CMD_IN_LAST, 0, ETHERNET_BUF_SIZE,
		    address, RECEIVE_INT,
		    DBDMA_WAIT_NEVER, 
		    DBDMA_BRANCH_NEVER);
    }

    /* stop when we hit the end of the list */
    DBDMA_BUILD(d, DBDMA_CMD_STOP, 0, 0, 0, RECEIVE_INT,
		DBDMA_WAIT_NEVER, DBDMA_BRANCH_NEVER);
    d++;

    /* branch to command at "address" ie. element 0 of the "array" */
    DBDMA_BUILD(d, DBDMA_CMD_NOP, 0, 0, 0, DBDMA_INT_NEVER,
		DBDMA_WAIT_NEVER, DBDMA_BRANCH_ALWAYS);
    address = (vm_offset_t) KVTOPHYS((vm_offset_t)m->rv_dma);
    dbdma_st4_endian(&d->d_cmddep, address);

    m->rv_head = 0;
    m->rv_tail = ETHER_RX_NUM_DBDMA_BUFS; /* always contains DBDMA_CMD_STOP */

    /* stop/init/restart dma channel */
    dbdma_reset(DBDMA_ETHERNET_RV);
    dbdma_reset(DBDMA_ETHERNET_TX);

    /* Set the wait value.. */
    regmap = DBDMA_REGMAP(DBDMA_ETHERNET_RV);
    dbdma_st4_endian(&regmap->d_wait, DBDMA_SET_CNTRL(0x00));

    /* Set the tx wait value */
    regmap = DBDMA_REGMAP(DBDMA_ETHERNET_TX);
    dbdma_st4_endian(&regmap->d_wait, DBDMA_SET_CNTRL(0x20));

    flush_cache_v((vm_offset_t)m->rv_dma, 
		  sizeof(dbdma_command_t) * (ETHER_RX_NUM_DBDMA_BUFS + 2));
    /* start receiving */
    dbdma_start(DBDMA_ETHERNET_RV, m->rv_dma);
}

#ifdef MACE_DEBUG
static unsigned char testBuffer[PG_SIZE * 4];
static unsigned char testMsg[] = "mace ethernet interface test";

static void
send_test_packet()
{
    unsigned char * tp;

    bzero(testBuffer, sizeof(testBuffer));

    tp = testBuffer;

    /* send self-addressed packet */
    bcopy(&mace.macaddr[0], tp, NUM_EN_ADDR_BYTES);
    tp += NUM_EN_ADDR_BYTES;
    bcopy(&mace.macaddr[0], tp, NUM_EN_ADDR_BYTES);
    tp += NUM_EN_ADDR_BYTES;
    *tp++ = 0;
    *tp++ = 0;
    bcopy(testMsg, tp, sizeof(testMsg));
    polled_send_pkt(testBuffer, 80);
    return;
}
#endif

/*
 * Function: init_mace
 *
 * Purpose:
 *   Called early on, initializes the adapter and readies it for
 *   kdb kernel debugging. 
 */
void
init_mace()
{
    unsigned char	status;
    mace_t *		m = &mace;
    struct mace_board * ereg;
    int 		mpc = 0;

    /*
     * Only use in-kernel driver for early debugging (bootargs: kdp=1 or kdp=3)
     */
    if ( (kdp_flag & 1) == 0 )
    {
      return;
    }

    bzero(&mace, sizeof(mace));

    /* get the ethernet registers' mapped address */
    ereg = m->ereg 
	= (struct mace_board *) POWERMAC_IO(PCI_ETHERNET_BASE_PHYS);
    mace_get_hwid((unsigned char *)POWERMAC_IO(PCI_ETHERNET_ADDR_PHYS), m);

    /* Reset the board & AMIC.. */
    mace_reset();

    /* grab the MACE chip rev  */
    m->chip_id = (ereg->chipid2 << 8 | ereg->chipid1);

    /* don't auto-strip for 802.3 */
    m->ereg->rcvfc &= ~(RCVFC_ASTRPRCV);

    /* set the ethernet address */
    mace_seteh(mace.macaddr);
    {
	unsigned char macaddr[NUM_EN_ADDR_BYTES];
	mace_geteh(macaddr);
	printf("mace ethernet [%02x:%02x:%02x:%02x:%02x:%02x]\n",
		macaddr[0], macaddr[1], macaddr[2], 
		macaddr[3], macaddr[4], macaddr[5]);
    }

    /* Now clear the Multicast filter */
    if (m->chip_id != MACE_REVISION_A2) {
	ereg->iac = IAC_ADDRCHG|IAC_LOGADDR; eieio();

	while ((status = ereg->iac)) {
	    if ((status & IAC_ADDRCHG) == 0)
		break;
	    eieio();
	}
	eieio();
    }
    else {
	ereg->iac = IAC_LOGADDR; eieio();
    }
    {
	int i;

	for (i=0; i < 8; i++) 
	{    ereg->ladrf = 0;
	     eieio();
        }
    }

    /* register interrupt routines */
    mace_setup_dbdma();

    /* Start the chip... */
    m->ereg->maccc = MACCC_ENXMT|MACCC_ENRCV; eieio();
    {
	volatile char ch =  mace.ereg->ir; eieio();
    }

    delay(500); /* paranoia */
    mace.ereg->imr = 0xfe; eieio();

    /* register our debugger routines */
    kdp_register_send_receive((kdp_send_t)polled_send_pkt, 
			      (kdp_receive_t)polled_receive_pkt);

#if 0
    printf("Testing 1 2 3\n");
    send_test_packet();
    printf("Testing 1 2 3\n");
    send_test_packet();
    printf("Testing 1 2 3\n");
    send_test_packet();
    do {
	static unsigned char buf[ETHERNET_BUF_SIZE];
	int len;
	int nmpc = mace.ereg->mpc; eieio();

	if (nmpc > mpc) {
	    mpc = nmpc;
	    printf("mpc %d\n", mpc);
	}
	polled_receive_pkt(buf, &len, 100);
	if (len > 0) {
	    printf("rx %d\n", len);
	    printContiguousEtherPacket(buf, len);
	}
    } while(1);
#endif

    return;
}

#ifdef MACE_DEBUG
static void
txstatus(char * msg)
{
    volatile dbdma_regmap_t *	dmap = DBDMA_REGMAP(DBDMA_ETHERNET_TX);
    volatile unsigned long 		status;
    volatile unsigned long 		intr;
    volatile unsigned long 		branch;
    volatile unsigned long 		wait;

    status = dbdma_ld4_endian(&dmap->d_status); eieio();
    intr = dbdma_ld4_endian(&dmap->d_intselect); eieio();
    branch = dbdma_ld4_endian(&dmap->d_branch); eieio();
    wait = dbdma_ld4_endian(&dmap->d_wait); eieio();
    printf("(%s s=0x%x i=0x%x b=0x%x w=0x%x)", msg, status, intr, branch,
	   wait);
    return;
}
#endif

static void
tx_dbdma(char * data, int len)
{
    unsigned long	count;
    dbdma_command_t *	d;
    unsigned long 	page;

    d = mace.tx_dma;
    page = ((unsigned long) data) & PG_MASK;
    if ((page + len) <= PG_SIZE) { /* one piece dma */
	DBDMA_BUILD(d, DBDMA_CMD_OUT_LAST, DBDMA_KEY_STREAM0,
		    len,
		    (vm_offset_t) KVTOPHYS((vm_offset_t) data),
		    DBDMA_INT_NEVER, 
		    DBDMA_WAIT_IF_FALSE, DBDMA_BRANCH_NEVER);
    }
    else { /* two piece dma */
	count = PG_SIZE - page;
	DBDMA_BUILD(d, DBDMA_CMD_OUT_MORE, DBDMA_KEY_STREAM0,
		    count,
		    (vm_offset_t)KVTOPHYS((vm_offset_t) data),
		    DBDMA_INT_NEVER, 
		    DBDMA_WAIT_NEVER, DBDMA_BRANCH_NEVER);
	d++;
	DBDMA_BUILD(d, DBDMA_CMD_OUT_LAST, DBDMA_KEY_STREAM0, 
		    len - count, (vm_offset_t)
		    KVTOPHYS((vm_offset_t)((unsigned char *)data + count)),
		    DBDMA_INT_NEVER, 
		    DBDMA_WAIT_IF_FALSE, DBDMA_BRANCH_NEVER);
    }
    d++;
    DBDMA_BUILD(d, DBDMA_CMD_LOAD_QUAD, DBDMA_KEY_SYSTEM,
		1, KVTOPHYS((vm_offset_t) &mace.ereg->xmtfs),DBDMA_INT_NEVER, 
		DBDMA_WAIT_NEVER, DBDMA_BRANCH_NEVER);
    d++;
    DBDMA_BUILD(d, DBDMA_CMD_LOAD_QUAD, DBDMA_KEY_SYSTEM,
		1, KVTOPHYS((vm_offset_t) &mace.ereg->ir), DBDMA_INT_ALWAYS,
		DBDMA_WAIT_NEVER, DBDMA_BRANCH_NEVER);
    d++;
    DBDMA_BUILD(d, DBDMA_CMD_STOP, 0, 0, 0, 0, 0, 0);
    flush_cache_v((vm_offset_t)mace.tx_dma, sizeof(dbdma_command_t) * TX_NUM_DBDMA);
    dbdma_start(DBDMA_ETHERNET_TX, mace.tx_dma);
    return;

}

static void
waitForDBDMADone(char * msg)
{
    {
	/* wait for tx dma completion */
	volatile dbdma_regmap_t *	dmap = DBDMA_REGMAP(DBDMA_ETHERNET_TX);
	int 				i;
	volatile unsigned long 		val;

	i = 0;
	do {
	    val = dbdma_ld4_endian(&dmap->d_status); eieio();
	    delay(50);
	    i++;
	} while ((i < 100000) && (val & DBDMA_CNTRL_ACTIVE));
	if (i == 100000)
	    printf("mace(%s): tx_dbdma poll timed out 0x%x", msg, val);
    }
}

void
mace_service_queue(struct ifnet * ifp)
{
    unsigned char * 	buf_p;
    struct mbuf * 	m;
    struct mbuf *       mp;
    int			len;

    if (mace.tx_busy) { /* transmit in progress? */
	return;
    }

    IF_DEQUEUE(&(ifp->if_snd), m);
    if (m == 0) {
        return;
    }

    len = m->m_pkthdr.len;

    if (len > ETHERMAXPACKET) {
	printf("mace_start: packet too big (%d), dropping\n", len);
	m_freem(m);
	return;
	
    }
    buf_p = mace.tx_dma_area;
    if (m->m_nextpkt) {
	printf("mace: sending more than one mbuf\n");
    }
    for (mp = m; mp; mp = mp->m_next) {
	if (mp->m_len == 0)
	    continue;
	bcopy(mtod(mp, caddr_t), buf_p, min(mp->m_len, len));
	len -= mp->m_len;
	buf_p += mp->m_len;
    }
    m_freem(m);

#if NBPFILTER > 0
    if (ifp->if_bpf)
	BPF_TAP(ifp->if_bpf, mace.tx_dma_area, m->m_pkthdr.len);
#endif

#if 0
    printf("tx packet %d\n", m->m_pkthdr.len);
    printContiguousEtherPacket(mace.tx_dma_area, m->m_pkthdr.len);
#endif

    /* fill in the dbdma records and kick off the dma */
    tx_dbdma(mace.tx_dma_area, m->m_pkthdr.len);
    mace.tx_busy = 1;
    return;
}

#ifdef MACE_DEBUG
static int
mace_watchdog()
{
    struct ifnet * ifp = &mace.en_arpcom.ac_if;
    int s;

    mace.txwatchdog++;
    s = splnet();
    if (mace.rxintr == 0) {
      printf("rx is hung up\n");
      rx_intr();
    }
    mace.rxintr = 0;
#if 0
    if (mace.txintr == 0 && ifp->if_snd.ifq_head) {
	if (mace.tx_busy)
	    dbdma_stop(DBDMA_ETHERNET_TX);
	mace.tx_busy = 0;
	mace_service_queue(ifp);
    }
    mace.txintr = 0;
#endif
    timeout(mace_watchdog, 0, 10*hz); /* just in case we drop an interrupt */
    return (0);
}
#endif /* MACE_DEBUG */

static int
mace_start(struct ifnet	* ifp)
{
//    int i = mace.tx_busy;

//    printf("mace_start %s\n", mace.tx_busy ? "(txBusy)" : "");
    mace_service_queue(ifp);

//    if (mace.tx_busy && !i)
//	printf("(txStarted)\n");
    return 0;
}

int
mace_recv_pkt(funcptr pktfunc, void * p)
{
    vm_offset_t			address;
    struct mace_board *		board;
    long			bytes;
    int				done = 0;
    int				doContinue = 0;
    mace_t *			m;
    unsigned long		resid;
    unsigned short		status;
    int				tail;

    m = &mace;
    board = m->ereg;

    /* remember where the tail was */
    tail = m->rv_tail;
    for (done = 0; (done == 0) && (m->rv_head != tail);) {
	dbdma_command_t *	dmaHead;
	
	dmaHead = &m->rv_dma[m->rv_head];
	resid = dbdma_ld4_endian(&dmaHead->d_status_resid);
	status = (resid >> 16);
	bytes  = resid & 0xffff;
	bytes = ETHERNET_BUF_SIZE - bytes - 8; /* strip off FCS/CRC */

	if ((status & DBDMA_ETHERNET_EOP) == 0)  {
	    /* no packets are ready yet */
	    break;
	}
	doContinue = 1;
	/* if the packet is good, pass it up */
	if (bytes >= (ETHER_MIN_PACKET - 4)) {
	    char * dmaPacket;
	    dmaPacket = &m->rv_dma_area[m->rv_head * ETHERNET_BUF_SIZE];
	    done = (*pktfunc)(dmaPacket, bytes, p);
	}
	/* mark the head as the new tail in the dma channel command list */
	DBDMA_BUILD(dmaHead, DBDMA_CMD_STOP, 0, 0, 0, RECEIVE_INT,
		    DBDMA_WAIT_NEVER, DBDMA_BRANCH_NEVER);
	flush_cache_v((vm_offset_t)dmaHead, sizeof(*dmaHead));
	eieio();

	/* make the tail an available dma'able entry */
	{
	    dbdma_command_t *		dmaTail;
	    dmaTail = &m->rv_dma[m->rv_tail];
	    address = KVTOPHYS((vm_offset_t) 
			       &m->rv_dma_area[m->rv_tail*ETHERNET_BUF_SIZE]);
	    // this command is live so write it carefully
	    DBDMA_ST4_ENDIAN(&dmaTail->d_address, address);
	    dmaTail->d_status_resid = 0;
	    dmaTail->d_cmddep = 0;
	    eieio();
	    DBDMA_ST4_ENDIAN(&dmaTail->d_cmd_count,
			    ((DBDMA_CMD_IN_LAST) << 28) | ((0) << 24) |
			    ((RECEIVE_INT) << 20) |
			    ((DBDMA_BRANCH_NEVER) << 18) | ((DBDMA_WAIT_NEVER) << 16) |
			    (ETHERNET_BUF_SIZE));
	    eieio();
	    flush_cache_v((vm_offset_t)dmaTail, sizeof(*dmaTail));
	}
	/* head becomes the tail */
	m->rv_tail = m->rv_head;

	/* advance the head */
	m->rv_head++;
	if (m->rv_head == (ETHER_RX_NUM_DBDMA_BUFS + 1))
	    m->rv_head = 0;
    }
    if (doContinue) {
	sync();
	dbdma_continue(DBDMA_ETHERNET_RV);
    }
    return (done);
}

/* kdb handle buffer routines */
struct kdbCopy {
    int *	len;
    char *	data;
};

static int
kdb_copy(char * pktBuf, int len, void * p)
{
    struct kdbCopy * cp = (struct kdbCopy *)p;

    bcopy(pktBuf, cp->data, len);
    *cp->len = len;
    return (1); /* signal that we're done */
}

/* kdb debugger routines */
static void
polled_send_pkt(char * data, int len)
{
    waitForDBDMADone("mace: polled_send_pkt start");
    tx_dbdma(data, len);
    waitForDBDMADone("mace: polled_send_pkt end");
    return;
}

static void
polled_receive_pkt(char *data, int *len, int timeout_ms)
{
    struct kdbCopy cp;

    cp.len = len;
    cp.data = data;

    timeout_ms *= 1000;
    *len = 0;
    while (mace_recv_pkt(kdb_copy, (void *)&cp) == 0) {
	if (timeout_ms <= 0)
	    break;
	delay(50);
	timeout_ms -= 50;
    }
    return;
}

/* Bump to force ethernet data to be 4-byte aligned
 *  (since the ethernet header is 14 bytes, and the 802.3 header is
 *  22 = 14+8 bytes).  This assumes that m_data is word-aligned
 *  (which it is).
 */
#define ETHER_DATA_ALIGN	2

/*
 * Function: rxpkt
 *
 * Purpose:
 *   Called from within mace_recv_pkt to deal with a packet of data.
 *   rxpkt() allocates an mbuf(+cluser) and passes it up to the stacks.
 * Returns:
 *   0 if the packet was copied to an mbuf, 1 otherwise
 */
static int
rxpkt(char * data, int len, void * p)
{
    struct ether_header * 	eh_p = (struct ether_header *)data;
    struct ifnet * 		ifp = &mace.en_arpcom.ac_if;
    struct mbuf *		m;

    int				interesting;

    mace.rxintr++;

    /* mcast, bcast -- we're interested in either */
    interesting = eh_p->ether_dhost[0] & 1;

#if NBPFILTER > 0
    /*
     * Check if there's a bpf filter listening on this interface.
     * If so, hand off the raw packet to bpf_tap().
     */
    if (ifp->if_bpf) {
	BPF_TAP(ifp->if_bpf, data, len);

	/*
	 * Keep the packet if it's a broadcast or has our
	 * physical ethernet address (or if we support
	 * multicast and it's one).
	 */
	if ((interesting == 0) && bcmp(eh_p->ether_dhost, mace.macaddr,
	   sizeof(eh_p->ether_dhost)) != 0) {
	return (1);
    }
    }
#endif

    /*
     * We "know" a full-sized packet fits in one cluster.  Set up the
     *  packet header, and if the length is sufficient, attempt to allocate
     *  a cluster.  If that fails, fall back to the old way (m_devget()).
     *  Here, we take the simple approach of cluster vs. single mbuf.
     */
    MGETHDR(m, M_DONTWAIT, MT_DATA);
    if (m == 0) {
#ifdef MACE_DEBUG
	printf("mget failed\n");
#endif
	return (1);
    }

    if (len > (MHLEN - ETHER_DATA_ALIGN))
    {   MCLGET(m, M_DONTWAIT);
	if (m->m_flags&M_EXT)	/* MCLGET succeeded */
	{	m->m_data += ETHER_DATA_ALIGN;
		bcopy(data, mtod(m, caddr_t), (unsigned)len);
	} else
	{
#ifdef MACE_DEBUG
		printf("no clusters\n");
#endif
		m_free(m);
		m = (struct mbuf *)m_devget(data, len, 0, ifp, 0);
		if (m == 0)
			return (1);
	}
    } else
    {	m->m_data += ETHER_DATA_ALIGN;
	bcopy(data, mtod(m, caddr_t), (unsigned)len);
    }

    /*
     * Current code up the line assumes that the media header's been
     *  stripped, but we'd like to preserve it, just in case someone
     *  wants to peek.
     */
    m->m_pkthdr.len = len;
    m->m_len = len;
    m->m_pkthdr.rcvif = ifp;
    m->m_data += sizeof(*eh_p);
    m->m_len -= sizeof (*eh_p);
    m->m_pkthdr.len -= sizeof(*eh_p);
    ether_input(ifp, eh_p, m);

    return (0);
}


static void
rx_intr()
{
    mace_recv_pkt(rxpkt, 0);
}

void
mace_dbdma_rx_intr(int unit, void *ignored, void * arp)
{
    if (!mace.ready)
	return;

    thread_call_func((thread_call_func_t)rx_intr, 0, TRUE);
}


int
mace_ioctl(struct ifnet * ifp,u_long cmd, caddr_t data)
{
	struct arpcom *			ar;
	unsigned 			error = 0;
	struct ifaddr *			ifa = (struct ifaddr *)data;
	struct ifreq *			ifr = (struct ifreq *)data;
	struct sockaddr_in * 		sin;

	sin = (struct sockaddr_in *)(&((struct ifreq *)data)->ifr_addr);
	ar = (struct arpcom *)ifp;

	switch (cmd) {
	  case SIOCAUTOADDR:
	    error = in_bootp(ifp, sin, &mace.en_arpcom.ac_enaddr);
	    break;

	case SIOCSIFADDR:
#if NeXT
		ifp->if_flags |= (IFF_UP | IFF_RUNNING);
#else
		ifp->if_flags |= IFF_UP;
#endif
		switch (ifa->ifa_addr->sa_family) {
		case AF_INET:
			/*
			 * See if another station has *our* IP address.
			 * i.e.: There is an address conflict! If a
			 * conflict exists, a message is sent to the
			 * console.
			 */
			if (IA_SIN(ifa)->sin_addr.s_addr != 0) { /* don't bother for 0.0.0.0 */
			ar->ac_ipaddr = IA_SIN(ifa)->sin_addr;
			arpwhohas(ar, &IA_SIN(ifa)->sin_addr);
			}
			break;
		default:
			break;
		}
		break;

	case SIOCSIFFLAGS:
		/*
		 * If interface is marked down and it is running, then stop it
		 */
		if ((ifp->if_flags & IFF_UP) == 0 &&
		    (ifp->if_flags & IFF_RUNNING) != 0) {
			/*
			 * If interface is marked down and it is running, then
			 * stop it.
			 */
			ifp->if_flags &= ~IFF_RUNNING;
		} else if ((ifp->if_flags & IFF_UP) != 0 &&
		    	   (ifp->if_flags & IFF_RUNNING) == 0) {
			/*
			 * If interface is marked up and it is stopped, then
			 * start it.
			 */
			ifp->if_flags |= IFF_RUNNING;
		}

		/*
		 * If the state of the promiscuous bit changes, the
		 * interface must be reset to effect the change.
		 */
		if (((ifp->if_flags ^ mace.promisc) & IFF_PROMISC) &&
		    (ifp->if_flags & IFF_RUNNING)) {
			mace.promisc = ifp->if_flags & IFF_PROMISC;
			mace_sync_promisc(ifp);
		}

		break;

	case SIOCADDMULTI:
		if ((error = ether_addmulti(ifr, ar)) == ENETRESET)
		{	if ((error = mace_addmulti(ifr, ar)) != 0)
			{	error = 0;
				mace_sync_mcast(ifp);
			}
		}
		break;

	case SIOCDELMULTI:
	        { 
		    struct ether_addr enaddr[2]; /* [0] - addrlo, [1] - addrhi */

		    if ((error = ether_delmulti(ifr, ar, enaddr)) == ENETRESET) {
			if ((error = mace_delmulti(ifr, ar, enaddr)) != 0) {
			    error = 0;
			    mace_sync_mcast(ifp);
			}
		    }
		}
		break;

	default:
	    error = EINVAL;
	    break;
    }
    return (error);
}

void
mace_init()
{
    struct ifnet * ifp = &mace.en_arpcom.ac_if;

    /*
     * Only use in-kernel driver for early debugging (bootargs: kdp=1|3)
     */
    if ( (kdp_flag & 1) == 0 )
    {
      return;
    }

    mace.tx_busy = 0;
    mace.txintr = 0;
    mace.promisc = 0;

    bzero((caddr_t)ifp, sizeof(struct ifnet));
    bcopy(&mace.macaddr, &mace.en_arpcom.ac_enaddr, NUM_EN_ADDR_BYTES);

    ifp->if_name = "en";
    ifp->if_unit = 0;
    ifp->if_private = 0;
    ifp->if_ioctl = mace_ioctl;
    ifp->if_start = mace_start;
    ifp->if_flags =
	IFF_BROADCAST | IFF_SIMPLEX | IFF_NOTRAILERS | IFF_MULTICAST;
#if NBPFILTER > 0
    bpfattach(&ifp->if_bpf, ifp, DLT_EN10MB, sizeof(struct ether_header));
#endif
    if_attach(ifp);
    ether_ifattach(ifp);

    mace.rxintr = 0;

    /* wire in the interrupt routines */
    pmac_register_int(PMAC_DMA_ETHERNET_RX, SPLNET,
		      mace_dbdma_rx_intr, 0);
    pmac_register_int(PMAC_DMA_ETHERNET_TX, SPLNET,
		      mace_dbdma_tx_intr, 0);

//    pmac_register_int(PMAC_DEV_ETHERNET, SPLNET, mace_pci_intr);
    mace.ready = 1;
#ifdef MACE_DEBUG
    timeout(mace_watchdog, 0, 10*hz); /* just in case we drop an interrupt */
#endif
    return;
}

/*
 * mace_pci_intr
 *
 * Service MACE interrupt
 */

void
mace_pci_intr(int device, void *ssp)
{
    unsigned char	ir, retry, frame, packet, length;

    ir = mace.ereg->ir; eieio();	/* Clear Interrupt */
    packet = mace.ereg->mpc; eieio();
    length = mace.ereg->rntpc; eieio();

    printf("(txI)");

    if (ir & IR_XMTINT) {
	retry = mace.ereg->xmtrc; eieio();	/* Grab transmit retry count */
	frame = mace.ereg->xmtfs; eieio();
//	if (mace.ready)
//	    mace_dbdma_tx_intr(device, ssp);
    }
    return;
}

static void
tx_intr()
{
    mace.txintr++;
    mace.tx_busy = 0;
    mace_service_queue(&mace.en_arpcom.ac_if);
}

/* 
 * mace_dbdma_tx_intr
 *
 * DBDMA interrupt routine
 */
void
mace_dbdma_tx_intr(int unit, void *ignored, void * arg)
{
    if (!mace.ready)
	return;

    thread_call_func((thread_call_func_t)tx_intr, 0, TRUE);
    return;
}
