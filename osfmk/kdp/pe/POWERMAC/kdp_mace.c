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

#include <mach/boolean.h>
#include <mach/exception_types.h>
#include <mach/mach_types.h>

#include <ppc/proc_reg.h>
#include <ppc/pmap.h>
#include <pexpert/ppc/powermac.h>
#include <pexpert/ppc/dbdma.h>
#include <kdp/kdp_en_debugger.h>
#include <kdp/kdp_udp.h>

#include "kdp_mace.h"

struct kdp_mace_copy_desc {
    int *       len;
    char *      data;
};
static mace_t  mace;
 
#define MACE_DMA_AREA_SIZE \
                (ETHER_RX_NUM_DBDMA_BUFS * ETHERNET_BUF_SIZE + PG_SIZE)
static unsigned long 
	mace_rx_dma_area[(MACE_DMA_AREA_SIZE + 
				sizeof(long))/sizeof(long)];                
static unsigned long 
	mace_tx_dma_area[(ETHERNET_BUF_SIZE + PG_SIZE + 
				sizeof(long))/sizeof(long)];
 
#ifdef MACE_DEBUG
static unsigned char testBuffer[PG_SIZE * 4];
static unsigned char testMsg[] = "mace ethernet interface test";
#endif

static void polled_send_pkt(char * data, int len);
static void polled_receive_pkt(char *data, int *len, int timeout_ms);

void kdp_mace_reset(mace_t *);
void kdp_mace_geteh(unsigned char *);
void kdp_mace_setup_dbdma(void);
boolean_t kdp_mace_init(void * baseAddresses[3], unsigned char * netAddr);
#ifdef MACE_DEBUG
static void printContiguousEtherPacket(u_char *, int);
static void send_test_packet(void);
#endif

typedef int (*funcptr)(char *, int, void *);
int kdp_mace_recv_pkt(funcptr , void *);

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

static void
printContiguousEtherPacket(u_char * data_p, int n_bytes)
{
    printEtherPacket((enet_addr_t *)data_p, 
		     (enet_addr_t *)(data_p + NUM_EN_ADDR_BYTES), 
		     *((u_short *)(data_p + (NUM_EN_ADDR_BYTES * 2))),
		     data_p, n_bytes);
}
#endif


/*
 * kdp_mace_reset
 *
 * Reset the board..
 */
void
kdp_mace_reset(mace_t * m)
{
    dbdma_reset(m->rv_dbdma);
    dbdma_reset(m->tx_dbdma);
}


/*
 * kdp_mace_geteh:
 *
 *	This function gets the ethernet address (array of 6 unsigned
 *	bytes) from the MACE board registers.
 *
 */
void
kdp_mace_geteh(unsigned char *ep)
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
mace_seteh(unsigned char *ep)
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
 * kdp_mace_setup_dbdma
 *
 * Setup various dbdma pointers.
 */
void
kdp_mace_setup_dbdma()
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
	address = (vm_offset_t) kvtophys((vm_offset_t)&m->rv_dma_area[i*ETHERNET_BUF_SIZE]);
	DBDMA_BUILD(d, DBDMA_CMD_IN_LAST, 0, ETHERNET_BUF_SIZE,
		    address, DBDMA_INT_ALWAYS,
		    DBDMA_WAIT_NEVER, 
		    DBDMA_BRANCH_NEVER);
    }

    /* stop when we hit the end of the list */
    DBDMA_BUILD(d, DBDMA_CMD_STOP, 0, 0, 0, DBDMA_INT_ALWAYS,
		DBDMA_WAIT_NEVER, DBDMA_BRANCH_NEVER);
    d++;

    /* branch to command at "address" ie. element 0 of the "array" */
    DBDMA_BUILD(d, DBDMA_CMD_NOP, 0, 0, 0, DBDMA_INT_NEVER,
		DBDMA_WAIT_NEVER, DBDMA_BRANCH_ALWAYS);
    address = (vm_offset_t) kvtophys((vm_offset_t)m->rv_dma);
    dbdma_st4_endian(&d->d_cmddep, address);

    m->rv_head = 0;
    m->rv_tail = ETHER_RX_NUM_DBDMA_BUFS; /* always contains DBDMA_CMD_STOP */
    regmap = m->rv_dbdma;

    /* stop/init/restart dma channel */
    dbdma_reset(regmap);
    dbdma_reset(m->tx_dbdma);

    /* Set the wait value.. */
    dbdma_st4_endian(&regmap->d_wait, DBDMA_SET_CNTRL(0x00));

    /* Set the tx wait value */
    regmap = m->tx_dbdma;
    dbdma_st4_endian(&regmap->d_wait, DBDMA_SET_CNTRL(0x20));

    flush_dcache((vm_offset_t)m->rv_dma, 
		  sizeof(dbdma_command_t) * (ETHER_RX_NUM_DBDMA_BUFS + 2),
			FALSE);
    /* start receiving */
    dbdma_start(m->rv_dbdma, m->rv_dma);
}

#ifdef MACE_DEBUG
static void
send_test_packet()
{
    unsigned char * tp;

    bzero((char *)testBuffer, sizeof(testBuffer));

    tp = testBuffer;

    /* send self-addressed packet */
    bcopy((char *)&mace.macaddr[0], (char *)tp, NUM_EN_ADDR_BYTES);
    tp += NUM_EN_ADDR_BYTES;
    bcopy((char *)&mace.macaddr[0], (char *)tp, NUM_EN_ADDR_BYTES);
    tp += NUM_EN_ADDR_BYTES;
    *tp++ = 0;
    *tp++ = 0;
    bcopy((char *)testMsg, (char *)tp, sizeof(testMsg));
    polled_send_pkt((char *)testBuffer, 80);
    return;
}
#endif

/*
 * Function: kdp_mace_init
 *
 * Purpose:
 *   Called early on, initializes the adapter and readies it for
 *   kdb kernel debugging. 
 */
boolean_t
kdp_mace_init(void * baseAddresses[3], unsigned char * netAddr)
{
    unsigned char	status;
    mace_t *		m = &mace;
    struct mace_board * ereg;
    int 		mpc = 0;
    int			i;

    bzero((char *)&mace, sizeof(mace));

    /* get the ethernet registers' mapped address */
    ereg = m->ereg 
	= (struct mace_board *) baseAddresses[0];
    m->tx_dbdma = (dbdma_regmap_t *) baseAddresses[1];
    m->rv_dbdma = (dbdma_regmap_t *) baseAddresses[2];

    for (i = 0; i < NUM_EN_ADDR_BYTES; i++)
        m->macaddr[i] = netAddr[i];

    /* Reset the board & AMIC.. */
    kdp_mace_reset(m);

    /* grab the MACE chip rev  */
    m->chip_id = (ereg->chipid2 << 8 | ereg->chipid1);

    /* don't auto-strip for 802.3 */
    m->ereg->rcvfc &= ~(RCVFC_ASTRPRCV);

    /* set the ethernet address */
    mace_seteh(mace.macaddr);
    {
	unsigned char macaddr[NUM_EN_ADDR_BYTES];
	kdp_mace_geteh(macaddr);
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
    kdp_mace_setup_dbdma();

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

#ifdef MACE_DEBUG
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
	polled_receive_pkt((char *)buf, &len, 100);
	if (len > 0) {
	    printf("rx %d\n", len);
	    printContiguousEtherPacket(buf, len);
	}
    } while(1);
#endif

    return TRUE;
}

#ifdef MACE_DEBUG
static void
kdp_mace_txstatus(char * msg)
{
    dbdma_regmap_t *		dmap = mace.tx_dbdma;
    volatile unsigned long 	status;
    volatile unsigned long 	intr;
    volatile unsigned long 	branch;
    volatile unsigned long 	wait;

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
kdp_mace_tx_dbdma(char * data, int len)
{
    unsigned long	count;
    dbdma_command_t *	d;
    unsigned long 	page;

    d = mace.tx_dma;
    page = ((unsigned long) data) & PG_MASK;
    if ((page + len) <= PG_SIZE) { /* one piece dma */
	DBDMA_BUILD(d, DBDMA_CMD_OUT_LAST, DBDMA_KEY_STREAM0,
		    len,
		    (vm_offset_t) kvtophys((vm_offset_t) data),
		    DBDMA_INT_NEVER, 
		    DBDMA_WAIT_IF_FALSE, DBDMA_BRANCH_NEVER);
    }
    else { /* two piece dma */
	count = PG_SIZE - page;
	DBDMA_BUILD(d, DBDMA_CMD_OUT_MORE, DBDMA_KEY_STREAM0,
		    count,
		    (vm_offset_t)kvtophys((vm_offset_t) data),
		    DBDMA_INT_NEVER, 
		    DBDMA_WAIT_NEVER, DBDMA_BRANCH_NEVER);
	d++;
	DBDMA_BUILD(d, DBDMA_CMD_OUT_LAST, DBDMA_KEY_STREAM0, 
		    len - count, (vm_offset_t)
		    kvtophys((vm_offset_t)((unsigned char *)data + count)),
		    DBDMA_INT_NEVER, 
		    DBDMA_WAIT_IF_FALSE, DBDMA_BRANCH_NEVER);
    }
    d++;
    DBDMA_BUILD(d, DBDMA_CMD_LOAD_QUAD, DBDMA_KEY_SYSTEM,
		1, kvtophys((vm_offset_t) &mace.ereg->xmtfs),DBDMA_INT_NEVER, 
//		1, &mace.ereg->xmtfs,DBDMA_INT_NEVER, 
		DBDMA_WAIT_NEVER, DBDMA_BRANCH_NEVER);
    d++;
    DBDMA_BUILD(d, DBDMA_CMD_LOAD_QUAD, DBDMA_KEY_SYSTEM,
		1, kvtophys((vm_offset_t) &mace.ereg->ir), DBDMA_INT_ALWAYS,
//		1, &mace.ereg->ir, DBDMA_INT_ALWAYS,
		DBDMA_WAIT_NEVER, DBDMA_BRANCH_NEVER);
    d++;
    DBDMA_BUILD(d, DBDMA_CMD_STOP, 0, 0, 0, 0, 0, 0);

    flush_dcache((vm_offset_t)mace.tx_dma, 
		sizeof(dbdma_command_t) * TX_NUM_DBDMA,
		FALSE);
    dbdma_start(mace.tx_dbdma, mace.tx_dma);
    return;

}

static void
waitForDBDMADone(char * msg)
{
    {
	/* wait for tx dma completion */
	dbdma_regmap_t *	dmap = mace.tx_dbdma;
	int 			i;
	volatile unsigned long 	val;

	i = 0;
	do {
	    val = dbdma_ld4_endian(&dmap->d_status); eieio();
	    delay(50);
	    i++;
	} while ((i < 100000) && (val & DBDMA_CNTRL_ACTIVE));
	if (i == 100000)
	    printf("mace(%s): kdp_mace_tx_dbdma poll timed out 0x%x", msg, val);
    }
}

int
kdp_mace_recv_pkt(funcptr pktfunc, void * p)
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
	    dmaPacket = (char *)&m->rv_dma_area[m->rv_head * ETHERNET_BUF_SIZE];
	    done = (*pktfunc)(dmaPacket, bytes, p);
	}
	/* mark the head as the new tail in the dma channel command list */
	DBDMA_BUILD(dmaHead, DBDMA_CMD_STOP, 0, 0, 0, DBDMA_INT_ALWAYS,
		    DBDMA_WAIT_NEVER, DBDMA_BRANCH_NEVER);
	flush_dcache((vm_offset_t)dmaHead, 
		sizeof(*dmaHead),
		FALSE);
	eieio();

	/* make the tail an available dma'able entry */
	{
	    dbdma_command_t *		dmaTail;
	    dmaTail = &m->rv_dma[m->rv_tail];
	    address = kvtophys((vm_offset_t) 
			       &m->rv_dma_area[m->rv_tail*ETHERNET_BUF_SIZE]);
	    // this command is live so write it carefully
	    DBDMA_ST4_ENDIAN(&dmaTail->d_address, address);
	    dmaTail->d_status_resid = 0;
	    dmaTail->d_cmddep = 0;
	    eieio();
	    DBDMA_ST4_ENDIAN(&dmaTail->d_cmd_count,
			    ((DBDMA_CMD_IN_LAST) << 28) | ((0) << 24) |
			    ((DBDMA_INT_ALWAYS) << 20) |
			    ((DBDMA_BRANCH_NEVER) << 18) | ((DBDMA_WAIT_NEVER) << 16) |
			    (ETHERNET_BUF_SIZE));
	    eieio();
	    flush_dcache((vm_offset_t)dmaTail, 
			sizeof(*dmaTail),
			FALSE);
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
	dbdma_continue(m->rv_dbdma);
    }
    return (done);
}

static int
kdp_mace_copy(char * pktBuf, int len, void * p)
{
    struct kdp_mace_copy_desc * cp = (struct kdp_mace_copy_desc *)p;

    bcopy((char *)pktBuf, (char *)cp->data, len);
    *cp->len = len;
    return (1); /* signal that we're done */
}

/* kdb debugger routines */
static void
polled_send_pkt(char * data, int len)
{
    waitForDBDMADone("mace: polled_send_pkt start");
    kdp_mace_tx_dbdma(data, len);
    waitForDBDMADone("mace: polled_send_pkt end");
    return;
}

static void
polled_receive_pkt(char *data, int *len, int timeout_ms)
{
    struct kdp_mace_copy_desc cp;

    cp.len = len;
    cp.data = data;

    timeout_ms *= 1000;
    *len = 0;
    while (kdp_mace_recv_pkt(kdp_mace_copy, (void *)&cp) == 0) {
	if (timeout_ms <= 0)
	    break;
	delay(50);
	timeout_ms -= 50;
    }
    return;
}
