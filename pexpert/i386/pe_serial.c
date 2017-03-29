/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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
 * file: pe_serial.c
 *       Polled-mode 16x50 UART driver.
 */

#include <machine/machine_routines.h>
#include <pexpert/protos.h>
#include <pexpert/pexpert.h>

struct pe_serial_functions {
    void            (*uart_init) (void);
    void            (*uart_set_baud_rate) (int unit, uint32_t baud_rate);
    int             (*tr0) (void);
    void            (*td0) (int c);
    int             (*rr0) (void);
    int             (*rd0) (void);
};

static struct pe_serial_functions *gPESF;

static int uart_initted = 0;   /* 1 if init'ed */

#define DEFAULT_UART_BAUD_RATE 115200

static unsigned uart_baud_rate = DEFAULT_UART_BAUD_RATE;

// =============================================================================
// Legacy UART support using IO transactions to COM1 or COM2
// =============================================================================

#define LEGACY_UART_PORT_ADDR   COM1_PORT_ADDR
#define LEGACY_UART_CLOCK       1843200   /* 1.8432 MHz clock */

#define IO_WRITE(r, v)  outb(LEGACY_UART_PORT_ADDR + UART_##r, v)
#define IO_READ(r)      inb(LEGACY_UART_PORT_ADDR + UART_##r)

enum {
    COM1_PORT_ADDR = 0x3f8,
    COM2_PORT_ADDR = 0x2f8
};

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
    UART_MSR = 6,  /* modem status register         */
    UART_SCR = 7   /* scratch register              */
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
    UART_LSR_DR    = 0x01,
    UART_LSR_OE    = 0x02,
    UART_LSR_PE    = 0x04,
    UART_LSR_FE    = 0x08,
    UART_LSR_THRE  = 0x20
};

static int
legacy_uart_probe( void )
{
    /* Verify that the Scratch Register is accessible */

    IO_WRITE( SCR, 0x5a );
    if (IO_READ(SCR) != 0x5a) return 0;
    IO_WRITE( SCR, 0xa5 );
    if (IO_READ(SCR) != 0xa5) return 0;
    return 1;
}

static void
legacy_uart_set_baud_rate( __unused int unit, uint32_t baud_rate )
{
    const unsigned char lcr = IO_READ( LCR );
    unsigned long       div;

    if (baud_rate == 0) baud_rate = 9600;
    div = LEGACY_UART_CLOCK / 16 / baud_rate;
    IO_WRITE( LCR, lcr | UART_LCR_DLAB );
    IO_WRITE( DLM, (unsigned char)(div >> 8) );
    IO_WRITE( DLL, (unsigned char) div );
    IO_WRITE( LCR, lcr & ~UART_LCR_DLAB);
}

static int
legacy_uart_tr0( void )
{
    return (IO_READ(LSR) & UART_LSR_THRE);
}

static void
legacy_uart_td0( int c )
{
    IO_WRITE( THR, c );
}

static void
legacy_uart_init( void )
{
    /* Disable hardware interrupts */

    IO_WRITE( MCR, 0 );
    IO_WRITE( IER, 0 );

    /* Disable FIFO's for 16550 devices */

    IO_WRITE( FCR, 0 );

    /* Set for 8-bit, no parity, DLAB bit cleared */

    IO_WRITE( LCR, UART_LCR_8BITS );

    /* Set baud rate */

    gPESF->uart_set_baud_rate ( 0, uart_baud_rate );

    /* Assert DTR# and RTS# lines (OUT2?) */

    IO_WRITE( MCR, UART_MCR_DTR | UART_MCR_RTS );

    /* Clear any garbage in the input buffer */

    IO_READ( RBR );

    uart_initted = 1;
}

static int
legacy_uart_rr0( void ) 
{
    unsigned char lsr;

    lsr = IO_READ( LSR );

    if ( lsr & (UART_LSR_FE | UART_LSR_PE | UART_LSR_OE) )
    {
        IO_READ( RBR ); /* discard */
        return 0;
    }

    return (lsr & UART_LSR_DR);
}

static int
legacy_uart_rd0( void ) 
{
    return IO_READ( RBR );
}

static struct pe_serial_functions legacy_uart_serial_functions = {
    .uart_init = legacy_uart_init,
    .uart_set_baud_rate = legacy_uart_set_baud_rate,
    .tr0 = legacy_uart_tr0,
    .td0 = legacy_uart_td0,
    .rr0 = legacy_uart_rr0,
    .rd0 = legacy_uart_rd0
};

// =============================================================================
// MMIO UART (using PCH LPSS UART2)
// =============================================================================

#define MMIO_UART2_BASE_LEGACY  0xFE034000
#define MMIO_UART2_BASE         0xFE036000

#define MMIO_WRITE(r, v)  ml_phys_write_word(mmio_uart_base + MMIO_UART_##r, v)
#define MMIO_READ(r)      ml_phys_read_word(mmio_uart_base + MMIO_UART_##r)

enum {
    MMIO_UART_RBR = 0x0,   /* receive buffer Register   (R) */
    MMIO_UART_THR = 0x0,   /* transmit holding register (W) */
    MMIO_UART_DLL = 0x0,   /* DLAB = 1, divisor latch (LSB) */
    MMIO_UART_IER = 0x4,   /* interrupt enable register     */
    MMIO_UART_DLM = 0x4,   /* DLAB = 1, divisor latch (MSB) */
    MMIO_UART_FCR = 0x8,   /* fifo control register (W)     */
    MMIO_UART_LCR = 0xc,   /* line control register         */
    MMIO_UART_MCR = 0x10,  /* modem control register        */
    MMIO_UART_LSR = 0x14,  /* line status register          */
    MMIO_UART_SCR = 0x1c   /* scratch register              */
};

static vm_offset_t mmio_uart_base = 0;
 
static int
mmio_uart_present( void )
{
    MMIO_WRITE( SCR, 0x5a );
    if (MMIO_READ(SCR) != 0x5a) return 0;
    MMIO_WRITE( SCR, 0xa5 );
    if (MMIO_READ(SCR) != 0xa5) return 0;

    return 1;
}

static int
mmio_uart_probe( void )
{
    unsigned new_mmio_uart_base = 0;

    // if specified, mmio_uart overrides all probing
    if (PE_parse_boot_argn("mmio_uart", &new_mmio_uart_base, sizeof (new_mmio_uart_base)))
    {
        // mmio_uart=0 will disable mmio_uart support
        if (new_mmio_uart_base == 0) {
            return 0;
        }

        mmio_uart_base = new_mmio_uart_base;
        return 1;
    }

    // probe the two possible MMIO_UART2 addresses
    mmio_uart_base = MMIO_UART2_BASE;
    if (mmio_uart_present()) {
      return 1;
    }

    mmio_uart_base = MMIO_UART2_BASE_LEGACY;
    if (mmio_uart_present()) {
      return 1;
    }

    // no mmio uart found
    return 0;
}

static void
mmio_uart_set_baud_rate( __unused int unit, __unused uint32_t baud_rate )
{
    const unsigned char lcr = MMIO_READ( LCR );
    unsigned long       div;

    if (baud_rate == 0) baud_rate = 9600;
    div = LEGACY_UART_CLOCK / 16 / baud_rate;

    MMIO_WRITE( LCR, lcr | UART_LCR_DLAB );
    MMIO_WRITE( DLM, (unsigned char)(div >> 8) );
    MMIO_WRITE( DLL, (unsigned char) div );
    MMIO_WRITE( LCR, lcr & ~UART_LCR_DLAB);
}

static int
mmio_uart_tr0( void )
{
    return (MMIO_READ(LSR) & UART_LSR_THRE);
}

static void
mmio_uart_td0( int c )
{
    MMIO_WRITE( THR, c );
}

static void
mmio_uart_init( void )
{
    /* Disable hardware interrupts */

    MMIO_WRITE( MCR, 0 );
    MMIO_WRITE( IER, 0 );

    /* Disable FIFO's for 16550 devices */

    MMIO_WRITE( FCR, 0 );

    /* Set for 8-bit, no parity, DLAB bit cleared */

    MMIO_WRITE( LCR, UART_LCR_8BITS );

    /* Leave baud rate as set by firmware unless serialbaud boot-arg overrides */

    if (uart_baud_rate != DEFAULT_UART_BAUD_RATE) 
    {
        gPESF->uart_set_baud_rate ( 0, uart_baud_rate );
    }

    /* Assert DTR# and RTS# lines (OUT2?) */

    MMIO_WRITE( MCR, UART_MCR_DTR | UART_MCR_RTS );

    /* Clear any garbage in the input buffer */

    MMIO_READ( RBR );

    uart_initted = 1;
}

static int
mmio_uart_rr0( void ) 
{
    unsigned char lsr;

    lsr = MMIO_READ( LSR );

    if ( lsr & (UART_LSR_FE | UART_LSR_PE | UART_LSR_OE) )
    {
        MMIO_READ( RBR ); /* discard */
        return 0;
    }
    
    return (lsr & UART_LSR_DR);
}

static int
mmio_uart_rd0( void ) 
{
    return MMIO_READ( RBR );
}

static struct pe_serial_functions mmio_uart_serial_functions = {
    .uart_init = mmio_uart_init,
    .uart_set_baud_rate = mmio_uart_set_baud_rate,
    .tr0 = mmio_uart_tr0,
    .td0 = mmio_uart_td0,
    .rr0 = mmio_uart_rr0,
    .rd0 = mmio_uart_rd0
};

// =============================================================================
// Generic serial support below
// =============================================================================

int
serial_init( void )
{
    unsigned new_uart_baud_rate = 0;

    if (PE_parse_boot_argn("serialbaud", &new_uart_baud_rate, sizeof (new_uart_baud_rate)))
    {
        /* Valid divisor? */
        if (!((LEGACY_UART_CLOCK / 16) % new_uart_baud_rate)) {
            uart_baud_rate = new_uart_baud_rate;
        }
    }

    if ( mmio_uart_probe() )
    {
        gPESF = &mmio_uart_serial_functions;
        gPESF->uart_init();
        return 1;
    }
    else if ( legacy_uart_probe() )
    {
        gPESF = &legacy_uart_serial_functions;
        gPESF->uart_init();
        return 1;
    }
    else
    {
        return 0;
    }

}

static void
uart_putc(char c)
{
    if (uart_initted) {
        while (!gPESF->tr0());  /* Wait until THR is empty. */
        gPESF->td0(c);
    }
}

static int
uart_getc(void)
{
    if (uart_initted) {
        if (!gPESF->rr0())
            return -1;
        return gPESF->rd0();
    }
    return -1;
}

void
serial_putc( char c )
{
    uart_putc(c);
}

int
serial_getc( void )
{
    return uart_getc();
}
