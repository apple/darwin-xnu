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
 * Copyright 1996 1995 by Open Software Foundation, Inc. 1997 1996 1995 1994 1993 1992 1991  
 *              All Rights Reserved 
 *  
 * Permission to use, copy, modify, and distribute this software and 
 * its documentation for any purpose and without fee is hereby granted, 
 * provided that the above copyright notice appears in all copies and 
 * that both the copyright notice and this permission notice appear in 
 * supporting documentation. 
 *  
 * OSF DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE 
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
 * FOR A PARTICULAR PURPOSE. 
 *  
 * IN NO EVENT SHALL OSF BE LIABLE FOR ANY SPECIAL, INDIRECT, OR 
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM 
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN ACTION OF CONTRACT, 
 * NEGLIGENCE, OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION 
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. 
 * 
 */
/*
 * Copyright 1996 1995 by Apple Computer, Inc. 1997 1996 1995 1994 1993 1992 1991  
 *              All Rights Reserved 
 *  
 * Permission to use, copy, modify, and distribute this software and 
 * its documentation for any purpose and without fee is hereby granted, 
 * provided that the above copyright notice appears in all copies and 
 * that both the copyright notice and this permission notice appear in 
 * supporting documentation. 
 *  
 * APPLE COMPUTER DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE 
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
 * FOR A PARTICULAR PURPOSE. 
 *  
 * IN NO EVENT SHALL APPLE COMPUTER BE LIABLE FOR ANY SPECIAL, INDIRECT, OR 
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM 
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN ACTION OF CONTRACT, 
 * NEGLIGENCE, OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION 
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. 
 */
/*
 * MKLINUX-1.0DR2
 */
/* 
 * PMach Operating System
 * Copyright (c) 1995 Santa Clara University
 * All Rights Reserved.
 */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990,1989 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 * 
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 * 
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 *	File:	if_3c501.h
 *	Author: Philippe Bernadat
 *	Date:	1989
 * 	Copyright (c) 1989 OSF Research Institute 
 *
 * 	3COM Etherlink 3C501 Mach Ethernet drvier
 */
/*
  Copyright 1990 by Open Software Foundation,
Cambridge, MA.

		All Rights Reserved

  Permission to use, copy, modify, and distribute this software and
its documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appears in all copies and
that both the copyright notice and this permission notice appear in
supporting documentation, and that the name of OSF or Open Software
Foundation not be used in advertising or publicity pertaining to
distribution of the software without specific, written prior
permission.

  OSF DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE
INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS,
IN NO EVENT SHALL OSF BE LIABLE FOR ANY SPECIAL, INDIRECT, OR
CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN ACTION OF CONTRACT,
NEGLIGENCE, OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/



#define ENETPAD(n)      char n[15] 

/* 0x50f0a000 */
struct mace_board {
     volatile unsigned char   rcvfifo;  /* 00  receive fifo */
     ENETPAD(epad0);
     volatile unsigned char   xmtfifo;  /* 01  transmit fifo */
     ENETPAD(epad1);
     volatile unsigned char   xmtfc;    /* 02  transmit frame control */
     ENETPAD(epad2);
     volatile unsigned char   xmtfs;    /* 03  transmit frame status */
     ENETPAD(epad3);
     volatile unsigned char   xmtrc;    /* 04  transmit retry count */
     ENETPAD(epad4);
     volatile unsigned char   rcvfc;    /* 05  receive frame control -- 4 bytes */
     ENETPAD(epad5); 
     volatile unsigned char   rcvfs;    /* 06  receive frame status */
     ENETPAD(epad6);
     volatile unsigned char   fifofc;   /* 07  fifo frame count */
     ENETPAD(epad7);
     volatile unsigned char   ir;       /* 08  interrupt */
     ENETPAD(epad8);
     volatile unsigned char   imr;      /* 09  interrupt mask */
     ENETPAD(epad9);
     volatile unsigned char   pr;       /* 10  poll */
     ENETPAD(epad10);
     volatile unsigned char   biucc;    /* 11  bus interface unit configuration control */
     ENETPAD(epad11);
     volatile unsigned char   fifocc;   /* 12  fifo configuration control */
     ENETPAD(epad12);
     volatile unsigned char   maccc;    /* 13  media access control configuration control */
     ENETPAD(epad13);
     volatile unsigned char   plscc;    /* 14  physical layer signalling configuration control */
     ENETPAD(epad14);
     volatile unsigned char   phycc;    /* 15  physical layer configuration control */
     ENETPAD(epad15);
     volatile unsigned char   chipid1;  /* 16  chip identification LSB */
     ENETPAD(epad16);
     volatile unsigned char   chipid2;  /* 17  chip identification MSB */
     ENETPAD(epad17);
     volatile unsigned char   iac;      /* 18  internal address configuration */
     ENETPAD(epad18);
     volatile unsigned char   res1;     /* 19  */
     ENETPAD(epad19);
     volatile unsigned char   ladrf;    /* 20  logical address filter -- 8 bytes */
     ENETPAD(epad20);
     volatile unsigned char   padr;     /* 21  physical address -- 6 bytes */
     ENETPAD(epad21);
     volatile unsigned char   res2;     /* 22  */
     ENETPAD(epad22);
     volatile unsigned char   res3;     /* 23  */
     ENETPAD(epad23);
     volatile unsigned char   mpc;      /* 24  missed packet count */
     ENETPAD(epad24);
     volatile unsigned char   res4;     /* 25  */
     ENETPAD(epad25);
     volatile unsigned char   rntpc;    /* 26  runt packet count */
     ENETPAD(epad26);
     volatile unsigned char   rcvcc;    /* 27  receive collision count */
     ENETPAD(epad27);
     volatile unsigned char   res5;     /* 28  */
     ENETPAD(epad28);
     volatile unsigned char   utr;      /* 29  user test */
     ENETPAD(epad29);
     volatile unsigned char   res6;     /* 30  */
     ENETPAD(epad30);
     volatile unsigned char   res7;     /* 31  */
     };

/*
 * Chip Revisions..
 */

#define	MACE_REVISION_B0	0x0940
#define	MACE_REVISION_A2	0x0941

/* xmtfc */
#define XMTFC_DRTRY       0X80
#define XMTFC_DXMTFCS     0x08
#define XMTFC_APADXNT     0x01

/* xmtfs */
#define XMTFS_XNTSV  	0x80
#define XMTFS_XMTFS  	0x40
#define XMTFS_LCOL   	0x20
#define XMTFS_MORE   	0x10
#define XMTFS_ONE    	0x08
#define XMTFS_DEFER  	0x04
#define XMTFS_LCAR   	0x02
#define XMTFS_RTRY   	0x01

/* xmtrc */
#define XMTRC_EXDEF  0x80

/* rcvfc */
#define RCVFC_LLRCV       0x08
#define RCVFC_M_R         0x04
#define RCVFC_ASTRPRCV    0x01

/* rcvfs */
#define RCVFS_OFLO   	0x80
#define RCVFS_CLSN   	0x40
#define RCVFS_FRAM   	0x20
#define RCVFS_FCS    	0x10
#define RCVFS_REVCNT 	0x0f

/* fifofc */
#define	FIFOCC_XFW_8	0x00 
#define	FIFOCC_XFW_16	0x40 
#define	FIFOCC_XFW_32	0x80 
#define	FIFOCC_XFW_XX	0xc0 
#define	FIFOCC_RFW_16	0x00 
#define	FIFOCC_RFW_32	0x10 
#define	FIFOCC_RFW_64	0x20 
#define	FIFOCC_RFW_XX	0x30 
#define FIFOCC_XFWU	0x08	
#define FIFOCC_RFWU	0x04	
#define FIFOCC_XBRST	0x02	
#define FIFOCC_RBRST	0x01	


/* ir */
#define IR_JAB    	0x80
#define IR_BABL   	0x40
#define IR_CERR   	0x20
#define IR_RCVCCO 	0x10
#define IR_RNTPCO 	0x08
#define IR_MPCO   	0x04
#define IR_RCVINT 	0x02
#define IR_XMTINT 	0x01

/* imr */
#define IMR_MJAB    	0x80
#define IMR_MBABL   	0x40
#define IMR_MCERR   	0x20
#define IMR_MRCVCCO 	0x10
#define IMR_MRNTPCO 	0x08
#define IMR_MMPCO   	0x04
#define IMR_MRCVINT 	0x02
#define IMR_MXMTINT 	0x01

/* pr */
#define PR_XMTSV  	0x80
#define PR_TDTREQ 	0x40
#define PR_RDTREQ 	0x20

/* biucc */
#define BIUCC_BSWP        0x40
#define BIUCC_XMTSP04     0x00
#define BIUCC_XMTSP16     0x10
#define BIUCC_XMTSP64     0x20
#define BIUCC_XMTSP112    0x30
#define BIUCC_SWRST       0x01

/* fifocc */
#define FIFOCC_XMTFW08W    0x00
#define FIFOCC_XMTFW16W    0x40
#define FIFOCC_XMTFW32W    0x80

#define FIFOCC_RCVFW16     0x00     
#define FIFOCC_RCVFW32     0x10
#define FIFOCC_RCVFW64     0x20

#define FIFOCC_XMTFWU      0x08
#define FIFOCC_RCVFWU      0x04
#define FIFOCC_XMTBRST     0x02
#define FIFOCC_RCVBRST     0x01

/* maccc */
#define MACCC_PROM        0x80
#define MACCC_DXMT2PD     0x40
#define MACCC_EMBA        0x20
#define MACCC_DRCVPA      0x08
#define MACCC_DRCVBC      0x04
#define MACCC_ENXMT       0x02
#define MACCC_ENRCV       0x01

/* plscc */
#define PLSCC_XMTSEL      0x08
#define PLSCC_AUI         0x00
#define PLSCC_TENBASE     0x02
#define PLSCC_DAI         0x04
#define PLSCC_GPSI        0x06
#define PLSCC_ENPLSIO     0x01

/* phycc */
#define PHYCC_LNKFL       0x80
#define PHYCC_DLNKTST     0x40
#define PHYCC_REVPOL      0x20
#define PHYCC_DAPC        0x10
#define PHYCC_LRT         0x08
#define PHYCC_ASEL        0x04
#define PHYCC_RWAKE       0x02
#define PHYCC_AWAKE       0x01

/* iac */
#define IAC_ADDRCHG     0x80
#define IAC_PHYADDR     0x04
#define IAC_LOGADDR     0x02

/* utr */
#define UTR_RTRE        0x80
#define UTR_RTRD        0x40
#define UTR_RPA         0x20
#define UTR_FCOLL       0x10
#define UTR_RCVFCSE     0x08

#define UTR_NOLOOP      0x00
#define UTR_EXTLOOP     0x02
#define UTR_INLOOP      0x04
#define UTR_INLOOP_M    0x06

#define ENET_PHYADDR_LEN	6
#define ENET_HEADER         14

#define BFRSIZ		2048
#define ETHER_ADD_SIZE	6	/* size of a MAC address */
#define	DSF_LOCK	1
#define DSF_RUNNING	2
#define MOD_ENAL 1
#define MOD_PROM 2

/*
 * MACE Chip revision codes
 */
#define MACERevA2       0x0941
#define MACERevB0       0x0940

/*
 * Defines and device state
 * Dieter Siegmund (dieter@next.com) Thu Feb 27 18:25:33 PST 1997
 */

#define PG_SIZE         0x1000UL
#define PG_MASK         (PG_SIZE - 1UL)

#define ETHERMTU                1500
#define ETHER_RX_NUM_DBDMA_BUFS 32
#define ETHERNET_BUF_SIZE       (ETHERMTU + 36)
#define ETHER_MIN_PACKET        64
#define TX_NUM_DBDMA            6
#define NUM_EN_ADDR_BYTES   6

#define DBDMA_ETHERNET_EOP      0x40

typedef struct mace_s {
    struct mace_board *         ereg;   /* ethernet register set address */
    dbdma_regmap_t *		tx_dbdma;
    dbdma_regmap_t *		rv_dbdma;
    unsigned char               macaddr[NUM_EN_ADDR_BYTES]; /* mac address */
    int                         chip_id;
    dbdma_command_t             *rv_dma;
    dbdma_command_t             *tx_dma;
    unsigned char               *rv_dma_area;
    unsigned char               *tx_dma_area;
    int                         rv_tail;
    int                         rv_head;
} mace_t;


