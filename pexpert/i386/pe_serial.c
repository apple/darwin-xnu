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
 * file: pe_serial.c
 *       Polled-mode 16x50 UART driver.
 */

#include <pexpert/protos.h>
#include <pexpert/pexpert.h>

void	serial_putc(char);
int	serial_getc(void);
int	serial_init(void);

/* standard port addresses */
enum {
    COM1_PORT_ADDR = 0x3f8,
    COM2_PORT_ADDR = 0x2f8
};

/* UART register offsets */
enum {
    UART_RBR = 0,  /* receive buffer Register   (R) */
    UART_THR = 0,  /* transmit holding register (W) */
    UART_DLL = 0,  /* DLAB = 1, divisor latch (LSB) */
    UART_IER = 1,  /* interrupt enable register     */
    UART_DLM = 1,  /* DLAB = 1, divisor latch (MSB) */
    UART_IIR = 2,  /* interrupt ident register (R)  */
    UART_FCR = 2,  /* fifo control register (W)     */
    UART_LCR = 3,  /* line control register         */
    UART_MCR = 4,  /* modem control register        */
    UART_LSR = 5,  /* line status register          */
    UART_MSR = 6   /* modem status register         */
};

enum {
    UART_LCR_8BITS = 0x03,
    UART_LCR_DLAB  = 0x80
};

enum {
    UART_MCR_DTR   = 0x01,
    UART_MCR_RTS   = 0x02,
    UART_MCR_OUT1  = 0x04,
    UART_MCR_OUT2  = 0x08,
    UART_MCR_LOOP  = 0x10
};

enum {
    UART_LSR_THRE  = 0x20
};

#define UART_BAUD_RATE  115200
#define UART_PORT_ADDR  COM1_PORT_ADDR

#define WRITE(r, v)  outb(UART_PORT_ADDR + UART_##r, v)
#define READ(r)      inb(UART_PORT_ADDR + UART_##r)
#define DELAY(x)     { volatile int _d_; for (_d_ = 0; _d_ < (10000*x); _d_++) ; }

static int uart_initted = 0;   /* 1 if init'ed */

static int
uart_probe( void )
{
    /* Verify that the Divisor Register is accessible */

    WRITE( LCR, UART_LCR_DLAB );
    WRITE( DLL, 0x5a );
    if (READ(DLL) != 0x5a) return 0;
    WRITE( DLL, 0xa5 );
    if (READ(DLL) != 0xa5) return 0;
    WRITE( LCR, 0x00 );
    return 1;
}

static void
uart_set_baud_rate( unsigned long baud_rate )
{
    #define UART_CLOCK  1843200   /* 1.8432 MHz clock */

    const unsigned char lcr = READ( LCR );
    unsigned long       div;

    if (baud_rate == 0) baud_rate = 9600;
    div = UART_CLOCK / 16 / baud_rate;
    WRITE( LCR, lcr | UART_LCR_DLAB );
    WRITE( DLM, (unsigned char)(div >> 8) );
    WRITE( DLL, (unsigned char) div );
    WRITE( LCR, lcr & ~UART_LCR_DLAB);
}

static void
uart_putc( char c )
{
    if (!uart_initted) return;

    /* Wait for THR empty */
    while ( !(READ(LSR) & UART_LSR_THRE) ) DELAY(1);

    WRITE( THR, c );
}

int serial_init( void )
{
    if ( /*uart_initted ||*/ uart_probe() == 0 ) return 0;

    /* Disable hardware interrupts */

    WRITE( MCR, 0 );
    WRITE( IER, 0 );

    /* Disable FIFO's for 16550 devices */

    WRITE( FCR, 0 );

    /* Set for 8-bit, no parity, DLAB bit cleared */

    WRITE( LCR, UART_LCR_8BITS );

    /* Set baud rate */

    uart_set_baud_rate( UART_BAUD_RATE );

    /* Assert DTR# and RTS# lines (OUT2?) */

    WRITE( MCR, UART_MCR_DTR | UART_MCR_RTS );

    /* Clear any garbage in the input buffer */

    READ( RBR );

    uart_initted = 1;

    return 1;
}

void serial_putc( char c )
{
    uart_putc(c);
    if (c == '\n') uart_putc('\r');
}

int serial_getc( void )
{
    return 0;  /* not supported */
}
