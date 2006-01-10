/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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
 * @OSF_COPYRIGHT@
 */
/* 
 */
 
/* 
 *	Olivetti Mach Console driver v0.0
 *	Copyright Ing. C. Olivetti & C. S.p.A. 1988, 1989
 *	All rights reserved.
 *
 */ 
/*
 *   Copyright 1988, 1989 by Olivetti Advanced Technology Center, Inc.,
 * Cupertino, California.
 * 
 * 		All Rights Reserved
 * 
 *   Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that the above copyright notice appears in all
 * copies and that both the copyright notice and this permission notice
 * appear in supporting documentation, and that the name of Olivetti
 * not be used in advertising or publicity pertaining to distribution
 * of the software without specific, written prior permission.
 * 
 *   OLIVETTI DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS,
 * IN NO EVENT SHALL OLIVETTI BE LIABLE FOR ANY SPECIAL, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN ACTION OF CONTRACT,
 * NEGLIGENCE, OR OTHER TORTIOUS ACTION, ARISING OUR OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * 
 *   Copyright 1988, 1989 by Intel Corporation, Santa Clara, California.
 * 
 * 		All Rights Reserved
 * 
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that the above copyright notice appears in all
 * copies and that both the copyright notice and this permission notice
 * appear in supporting documentation, and that the name of Intel
 * not be used in advertising or publicity pertaining to distribution
 * of the software without specific, written prior permission.
 * 
 * INTEL DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS,
 * IN NO EVENT SHALL INTEL BE LIABLE FOR ANY SPECIAL, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN ACTION OF CONTRACT,
 * NEGLIGENCE, OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $ Header:  $ */

#include <pexpert/pexpert.h>

extern void cpu_shutdown(void);

int	cngetc(void);
int	cnmaygetc(void);
void	kdreboot(void);

/*
 * Common I/O ports.
 */
#define K_RDWR          0x60    /* keyboard data & cmds (read/write) */
#define K_STATUS        0x64    /* keybd status (read-only) */
#define K_CMD           0x64    /* keybd ctlr command (write-only) */

/*
 * Bit definitions for K_STATUS port.
 */
#define K_OBUF_FUL      0x01    /* output (from keybd) buffer full */
#define K_IBUF_FUL      0x02    /* input (to keybd) buffer full */
#define K_SYSFLAG       0x04    /* "System Flag" */
#define K_CMD_DATA      0x08    /* 1 = input buf has cmd, 0 = data */
#define K_KBD_INHBT     0x10    /* 0 if keyboard inhibited */
#define K_XMT_TIMEOUT   0x20    /* Transmit time out */
#define K_RCV_TIMEOUT   0x40    /* Receive time out */

/* 
 * Keyboard controller commands (sent to K_CMD port).
 */
#define K_CMD_READ      0x20    /* read controller command byte */
#define K_CMD_WRITE     0x60    /* write controller command byte */
#define K_CMD_TEST      0xab    /* test interface */
#define K_CMD_DUMP      0xac    /* diagnostic dump */
#define K_CMD_DISBLE    0xad    /* disable keyboard */
#define K_CMD_ENBLE     0xae    /* enable keyboard */
#define K_CMD_RDKBD     0xc4    /* read keyboard ID */
#define K_CMD_ECHO      0xee    /* used for diagnostic testing */
#define K_CMD_RESET     0xfe    /* issue a system reset */

/* 
 * cngetc / cnmaygetc
 * 
 * Get one character using polling, rather than interrupts.
 * Used by the kernel debugger.
 */

int
cngetc(void)
{
    char c;

    if ( 0 == (*PE_poll_input)(0, &c) )
        return ( c );
    else
        return ( 0 );
}

int
cnmaygetc(void)
{
    char c;

    if ( 0 == (*PE_poll_input)(0, &c) )
        return ( c );
    else
        return ( 0 );
}

/*
 * kd_sendcmd
 *
 * This function sends a command byte to the keyboard command
 * port, but first waits until the input/output data buffer is
 * clear before sending the data.
 *
 */

static void
kd_sendcmd(unsigned char ch)
{
    while (inb(K_STATUS) & K_IBUF_FUL);
    outb(K_CMD, ch);
}

/*
 * kdreboot
 *
 * Send a command to the motherboard keyboard controller to
 * issue a hardware reset.
 */

void
kdreboot(void)
{
    kd_sendcmd( K_CMD_RESET );

    /*
     * DRAT.  We're still here.  Let's try a "CPU shutdown", which consists
     * of clearing the IDTR and causing an exception.  It's in locore.s
     */
    cpu_shutdown();
    /*NOTREACHED*/
}
