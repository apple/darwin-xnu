/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
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
 * 18 June 1998 sdouglas
 * Start IOKit version.
 */


/*
    File:       via6522.h

    Contains:   xxx put contents here xxx

    Written by: xxx put writers here xxx

    Copyright:  © 1993, 1995 by Apple Computer, Inc., all rights reserved.

    Change History (most recent first):

         <1>     2/22/95    AM      First checked in.
         <1>    04/04/94    MRN     First checked in.

*/

/*
 * Copyright 1987-91 Apple Computer, Inc.
 * All Rights Reserved.
 */

#ifndef __VIA6522_H__
#define __VIA6522_H__

/*
 *   Synertek SY6522 VIA Versatile Interface Adapter
 */

/*
 * This has been modified to address BOTH the via and RBV registers,
 * because we know that both chips ignore part of the address, thus
 * only responding correctly.  It's ugly, but the ROM does it...
 */

#if defined(powerc) || defined (__powerc)
#pragma options align=mac68k
#endif
 
typedef struct via6522Regs                      /* VIA / RBV address */
    {
    volatile unsigned char  vBufB;              /* 0000/0000 register b */  
    volatile unsigned char  RvExp;              /* 0001 RBV future expansion */
    volatile unsigned char  RvSlotIFR;          /* 0002 RBV Slot interrupts reg. */
    volatile unsigned char  RvIFR;              /* 0003 RBV interrupt flag reg. */
    unsigned char           jnk0[ 12 ];

    volatile unsigned char  RvMonP;             /* xxxx/0010 RBV video monitor type */
    volatile unsigned char  RvChpT;             /* xxxx/0011 RBV test mode register */
    volatile unsigned char  RvSlotIER;          /* xxxx/0012 RBV slot interrupt enables */
    volatile unsigned char  RvIER;              /* xxxx/0013 RBV interrupt flag enable reg */
    unsigned char           jnk1[ 0x1FF - 0x13 ];

    volatile unsigned char  vBufAH;             /* 0200 buffer a (with handshake). */
    unsigned char           jnk2[ 0x1FF ];      /* Dont use! Here only for completeness */

    volatile unsigned char  vDIRB;              /* 0400 data direction register B */
    unsigned char           jnk25[ 0x1FF ];

    volatile unsigned char  vDIRA;              /* 0600 data direction register A */
    unsigned char           jnk3[ 0x1FF ];

    volatile unsigned char  vT1C;               /* 0800 timer one low */
    unsigned char           jnk4[ 0x1FF ];

    volatile unsigned char  vT1CH;              /* 0A00 timer one high */
    unsigned char           jnk5[ 0x1FF ];

    volatile unsigned char  vT1L;               /* 0C00 timer one latches low */
    unsigned char           jnk6[ 0x1FF ];

    volatile unsigned char  vT1LH;              /* 0E00 timer one latches high */
    unsigned char           jnk7[ 0x1FF ];

    volatile unsigned char  vT2C;               /* 1000 timer 2 low */
    unsigned char           jnk8[ 0x1FF ];

    volatile unsigned char  vT2CH;              /* 1200 timer two counter high */
    unsigned char           jnk9[ 0x1FF ];

    volatile unsigned char  vSR;                /* 1400 shift register */   
    unsigned char           jnka[ 0x1FF ];

    volatile unsigned char  vACR;               /* 1600 auxilary control register */    
    unsigned char           jnkb[ 0x1FF ];

    volatile unsigned char  vPCR;               /* 1800 peripheral control register */
    unsigned char           jnkc[ 0x1FF ];

    volatile unsigned char  vIFR;               /* 1A00 interrupt flag register */
    unsigned char           jnkd[ 0x1FF ];

    volatile unsigned char  vIER;               /* 1C00 interrupt enable register */    
    unsigned char           jnkf[ 0x1FF ];

    volatile unsigned char  vBufA;              /* 1E00 register A, read and write */
    } via6522Regs;

#if defined(powerc) || defined(__powerc)
#pragma options align=reset
#endif


/*  Register B contents */

#define VRB_POWEROFF    0x04            /* disk head select */
#define RBV_POWEROFF    VRB_POWEROFF
#define VRB_BUSLOCK     0x02            /* NuBus Transactions are locked */


/*  Register A contents */

#define VRA_DRIVE       0x10            /* drive select */
#define VRA_HEAD        0x20            /* disk head select */


/*  Auxillary control register contents */

#define VAC_PAENL       0x01            /* Enable latch for PA */
#define VAC_PADISL      0x00            /* Disable latch for PA */
#define VAC_PBENL       0x02            /* Enable latch for PA */
#define VAC_PBDISL      0x00            /* Disable latch for PA */
#define VAC_SRDIS       0x00            /* Shift Reg Disabled */
#define VAC_SRMD1       0x04            /* Shift In under control of T2 */
#define VAC_SRMD2       0x08            /* Shift In under control of Phase 2 */
#define VAC_SRMD3       0x0C            /* Shift in under control of Ext Clk */
#define VAC_SRMD4       0x10            /* Shift Out free running at T2 rate */
#define VAC_SRMD5       0x14            /* Shift Out under control of T2 */
#define VAC_SRMD6       0x18            /* Shift Out under control of theta2 */
#define VAC_SRMD7       0x1C            /* Shift Out under control of Ext Clk */
#define VAC_T2CTL       0x20            /* Timer two, control */
#define VAC_T2TI        0x00            /* Timer Two, Timed Interrupt */
#define VAC_T2CD        0x20            /* Timer Two, count down with pulses on PB6 */
#define VAC_T1CONT      0x40            /* Timer one, continous counting */
#define VAC_T11SHOT     0x00            /* Timer One, one shot output */
#define VAC_T1PB7       0x80            /* Timer one, drives PB7 */
#define VAC_T1PB7DIS    0x00            /* Timer one, drives PB7 disabled */


/*  Interrupt enable register contents */

#define VIE_CA2         0x01            /* interrupt on CA2 */
#define VIE_CA1         0x02            /* interrupt on CA1 */
#define VIE_SR          0x04            /* Shift Register */
#define VIE_CB2         0x08            /* interrupt on CB2 */
#define VIE_CB1         0x10            /* interrupt on CB1 */
#define VIE_TIM2        0x20            /* timer 2 interrupt */
#define VIE_TIM1        0x40            /* timer 1 interrupt */
#define VIE_SET         0x80            /* Set interrupt bits if this is on */
#define VIE_CLEAR       0x00            /* Clear bits if used */

#define VIE_ALL         ( VIE_TIM1 | VIE_TIM2 | VIE_CB1 | VIE_CB2 | VIE_SR | VIE_CA1 | VIE_CA2 )


/*  VIA Data Direction Register Contents */

#define VDR_P7_O        0x80            /* P7 is output */
#define VDR_P7_I        0x00            /* P7 is input */
#define VDR_P6_O        0x40            /* P6 is output */
#define VDR_P6_I        0x00            /* P6 is input */
#define VDR_P5_O        0x20            /* P5 is output */
#define VDR_P5_I        0x00            /* P5 is input */
#define VDR_P4_O        0x10            /* P4 is output */
#define VDR_P4_I        0x00            /* P4 is input */
#define VDR_P3_O        0x08            /* P3 is output */
#define VDR_P3_I        0x00            /* P3 is input */
#define VDR_P2_O        0x04            /* P2 is output */
#define VDR_P2_I        0x00            /* P2 is input */
#define VDR_P1_O        0x02            /* P1 is output */
#define VDR_P1_I        0x00            /* P1 is input */
#define VDR_P0_O        0x01            /* P0 is output */
#define VDR_P0_I        0x00            /* P0 is input */


/*  VIA1 Register A contents where they differ from standard VIA1 */

#define RBV_BURNIN      0x01            /* burnin flag */
#define RBV_CPUID0      0x02            /* CPU id bit 0 */
#define RBV_CPUID1      0x04            /* CPU id bit 1 */
#define RBV_CPUID2      0x10            /* CPU id bit 2 */
#define RBV_CPUID3      0x40            /* CPU id bit 3 */


/*  VIA1 Register B contents where they differ from standard VIA1 */

#define RBV_PARDIS      0x40            /* disable parity */
#define RBV_PAROK       0x80            /* parity OK */

#define EVRB_XCVR       0x08            /* XCVR_SESSION* */
#define EVRB_FULL       0x10            /* VIA_FULL */
#define EVRB_SYSES      0x20            /* SYS_SESSION */
#define EVRB_AUXIE      0x00            /* Enable A/UX Interrupt Scheme */
#define EVRB_AUXID      0x40            /* Disable A/UX Interrupt Scheme */
#define EVRB_SFTWRIE    0x00            /* Software Interrupt ReQuest */
#define EVRB_SFTWRID    0x80            /* Software Interrupt ReQuest */


/*  VIA2 Register A contents where they differ from standard VIA2 */

#define RBV_SZEROIRQ    0x40            /* slot 0 irq */
#define EVRA_ENETIRQ    0x01            /* Ethernet irq */
#define EVRA_VIDIRQ     0x40            /* Video irq */


/*  VIA2 Register B contents where they differ from standard VIA2 */

#define RBV_CDIS        0x01            /* disable external cache */
#define RBV_CFLUSH      0x08            /* flush external cache */
#define EVRB_LED        0x10            /* LED */
#define RBV_PARODD      0x80            /* 1 for odd, 0 for even */


/*  Video monitor parameters: */
#define RBV_DEPTH       0x07            /* bits per pixel: 000=1,001=2,010=4,011=8 */
#define RBV_MONID       0x38            /* monitor type as below */
#define RBV_VIDOFF      0x40            /* 1 turns off onboard video */


/*  Supported video monitor types: */

#define MON_15BW        ( 1 << 3 )      /* 15" BW  portrait */
#define MON_IIGS        ( 2 << 3 )      /* modified IIGS monitor */
#define MON_15RGB       ( 5 << 3 )      /* 15" RGB portrait */
#define MON_12OR13      ( 6 << 3 )      /* 12" BW or 13" RGB */
#define MON_NONE        ( 7 << 3 )      /* No monitor attached */

#endif /* __VIA6522_H__ */
