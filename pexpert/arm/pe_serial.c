/*
 * Copyright (c) 2000-2015 Apple Inc. All rights reserved.
 */

/*
 * file: pe_serial.c Polled-mode UART0 driver for S3c2410 and PL011.
 */


#include <kern/clock.h>
#include <kern/debug.h>
#include <libkern/OSBase.h>
#include <libkern/section_keywords.h>
#include <mach/mach_time.h>
#include <machine/atomic.h>
#include <machine/machine_routines.h>
#include <pexpert/pexpert.h>
#include <pexpert/protos.h>
#include <pexpert/device_tree.h>
#if defined __arm__
#include <arm/caches_internal.h>
#include <arm/machine_routines.h>
#include <arm/proc_reg.h>
#include <pexpert/arm/board_config.h>
#include <vm/pmap.h>
#elif defined __arm64__
#include <pexpert/arm/consistent_debug.h>
#include <pexpert/arm64/board_config.h>
#include <arm64/proc_reg.h>
#endif

struct pe_serial_functions {
	void            (*uart_init) (void);
	void            (*uart_set_baud_rate) (int unit, uint32_t baud_rate);
	int             (*tr0) (void);
	void            (*td0) (int c);
	int             (*rr0) (void);
	int             (*rd0) (void);
	struct pe_serial_functions *next;
};

SECURITY_READ_ONLY_LATE(static struct pe_serial_functions*) gPESF = NULL;

static int         uart_initted = 0;    /* 1 if init'ed */
static vm_offset_t uart_base = 0;

/*****************************************************************************/

#ifdef  S3CUART

static int32_t dt_pclk      = -1;
static int32_t dt_sampling  = -1;
static int32_t dt_ubrdiv    = -1;

static void ln2410_uart_set_baud_rate(__unused int unit, uint32_t baud_rate);

static void
ln2410_uart_init(void)
{
	uint32_t ucon0 = 0x405; /* NCLK, No interrupts, No DMA - just polled */

	rULCON0 = 0x03;         /* 81N, not IR */

	// Override with pclk dt entry
	if (dt_pclk != -1) {
		ucon0 = ucon0 & ~0x400;
	}

	rUCON0 = ucon0;
	rUMCON0 = 0x00;         /* Clear Flow Control */

	ln2410_uart_set_baud_rate(0, 115200);

	rUFCON0 = 0x03;         /* Clear & Enable FIFOs */
	rUMCON0 = 0x01;         /* Assert RTS on UART0 */
}

static void
ln2410_uart_set_baud_rate(__unused int unit, uint32_t baud_rate)
{
	uint32_t div = 0;
	uint32_t uart_clock = 0;
	uint32_t sample_rate = 16;

	if (baud_rate < 300) {
		baud_rate = 9600;
	}

	if (rUCON0 & 0x400) {
		// NCLK
		uart_clock = (uint32_t)gPEClockFrequencyInfo.fix_frequency_hz;
	} else {
		// PCLK
		uart_clock = (uint32_t)gPEClockFrequencyInfo.prf_frequency_hz;
	}

	if (dt_sampling != -1) {
		// Use the sampling rate specified in the Device Tree
		sample_rate = dt_sampling & 0xf;
	}

	if (dt_ubrdiv != -1) {
		// Use the ubrdiv specified in the Device Tree
		div = dt_ubrdiv & 0xffff;
	} else {
		// Calculate ubrdiv. UBRDIV = (SourceClock / (BPS * Sample Rate)) - 1
		div = uart_clock / (baud_rate * sample_rate);

		uint32_t actual_baud = uart_clock / ((div + 0) * sample_rate);
		uint32_t baud_low    = uart_clock / ((div + 1) * sample_rate);

		// Adjust div to get the closest target baudrate
		if ((baud_rate - baud_low) > (actual_baud - baud_rate)) {
			div--;
		}
	}

	// Sample Rate [19:16], UBRDIV [15:0]
	rUBRDIV0 = ((16 - sample_rate) << 16) | div;
}

static int
ln2410_tr0(void)
{
	return rUTRSTAT0 & 0x04;
}
static void
ln2410_td0(int c)
{
	rUTXH0 = (unsigned)(c & 0xff);
}
static int
ln2410_rr0(void)
{
	return rUTRSTAT0 & 0x01;
}
static int
ln2410_rd0(void)
{
	return (int)rURXH0;
}

SECURITY_READ_ONLY_LATE(static struct pe_serial_functions) ln2410_serial_functions =
{
	.uart_init = ln2410_uart_init,
	.uart_set_baud_rate = ln2410_uart_set_baud_rate,
	.tr0 = ln2410_tr0,
	.td0 = ln2410_td0,
	.rr0 = ln2410_rr0,
	.rd0 = ln2410_rd0
};

#endif  /* S3CUART */

/*****************************************************************************/

static void
dcc_uart_init(void)
{
}

static unsigned int
read_dtr(void)
{
#ifdef __arm__
	unsigned int    c;
	__asm__ volatile (
                 "mrc p14, 0, %0, c0, c5\n"
 :               "=r"(c));
	return c;
#else
	/* ARM64_TODO */
	panic_unimplemented();
	return 0;
#endif
}
static void
write_dtr(unsigned int c)
{
#ifdef __arm__
	__asm__ volatile (
                 "mcr p14, 0, %0, c0, c5\n"
                 :
                 :"r"(c));
#else
	/* ARM64_TODO */
	(void)c;
	panic_unimplemented();
#endif
}

static int
dcc_tr0(void)
{
#ifdef __arm__
	return !(arm_debug_read_dscr() & ARM_DBGDSCR_TXFULL);
#else
	/* ARM64_TODO */
	panic_unimplemented();
	return 0;
#endif
}

static void
dcc_td0(int c)
{
	write_dtr(c);
}

static int
dcc_rr0(void)
{
#ifdef __arm__
	return arm_debug_read_dscr() & ARM_DBGDSCR_RXFULL;
#else
	/* ARM64_TODO */
	panic_unimplemented();
	return 0;
#endif
}

static int
dcc_rd0(void)
{
	return read_dtr();
}

SECURITY_READ_ONLY_LATE(static struct pe_serial_functions) dcc_serial_functions =
{
	.uart_init = dcc_uart_init,
	.uart_set_baud_rate = NULL,
	.tr0 = dcc_tr0,
	.td0 = dcc_td0,
	.rr0 = dcc_rr0,
	.rd0 = dcc_rd0
};

/*****************************************************************************/

#ifdef SHMCON

#define CPU_CACHELINE_SIZE      (1 << MMU_CLINE)

#ifndef SHMCON_NAME
#define SHMCON_NAME             "AP-xnu"
#endif

#define SHMCON_MAGIC            'SHMC'
#define SHMCON_VERSION          2
#define CBUF_IN                 0
#define CBUF_OUT                1
#define INBUF_SIZE              (panic_size / 16)
#define FULL_ALIGNMENT          (64)

#define FLAG_CACHELINE_32       1
#define FLAG_CACHELINE_64       2

/* Defines to clarify the master/slave fields' use as circular buffer pointers */
#define head_in         sidx[CBUF_IN]
#define tail_in         midx[CBUF_IN]
#define head_out        midx[CBUF_OUT]
#define tail_out        sidx[CBUF_OUT]

/* TODO: get from device tree/target */
#define NUM_CHILDREN            5

#define WRAP_INCR(len, x) do{ (x)++; if((x) >= (len)) (x) = 0; } while(0)
#define ROUNDUP(a, b) (((a) + ((b) - 1)) & (~((b) - 1)))

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define shmcon_barrier() do {__asm__ volatile("dmb ish" : : : "memory");} while(0)

struct shm_buffer_info {
	uint64_t        base;
	uint32_t        unused;
	uint32_t        magic;
};

struct shmcon_header {
	uint32_t        magic;
	uint8_t         version;
	uint8_t         children;       /* number of child entries in child_ent */
	uint16_t        flags;
	uint64_t        buf_paddr[2];   /* Physical address for buffers (in, out) */
	uint32_t        buf_len[2];
	uint8_t         name[8];

	/* Slave-modified data - invalidate before read */
	uint32_t        sidx[2] __attribute__((aligned(FULL_ALIGNMENT)));       /* In head, out tail */

	/* Master-modified data - clean after write */
	uint32_t        midx[2] __attribute__((aligned(FULL_ALIGNMENT)));       /* In tail, out head */

	uint64_t        child[0];       /* Physical address of child header pointers */
};

static volatile struct shmcon_header *shmcon = NULL;
static volatile uint8_t *shmbuf[2];
#ifdef SHMCON_THROTTLED
static uint64_t grace = 0;
static uint64_t full_timeout = 0;
#endif

static void
shmcon_set_baud_rate(__unused int unit, __unused uint32_t baud_rate)
{
	return;
}

static int
shmcon_tr0(void)
{
#ifdef SHMCON_THROTTLED
	uint32_t head = shmcon->head_out;
	uint32_t tail = shmcon->tail_out;
	uint32_t len = shmcon->buf_len[CBUF_OUT];

	WRAP_INCR(len, head);
	if (head != tail) {
		full_timeout = 0;
		return 1;
	}

	/* Full.  Is this buffer being serviced? */
	if (full_timeout == 0) {
		full_timeout = mach_absolute_time() + grace;
		return 0;
	}
	if (full_timeout > mach_absolute_time()) {
		return 0;
	}

	/* Timeout - slave not really there or not keeping up */
	tail += (len / 4);
	if (tail >= len) {
		tail -= len;
	}
	shmcon_barrier();
	shmcon->tail_out = tail;
	full_timeout = 0;
#endif
	return 1;
}

static void
shmcon_td0(int c)
{
	uint32_t head = shmcon->head_out;
	uint32_t len = shmcon->buf_len[CBUF_OUT];

	shmbuf[CBUF_OUT][head] = (uint8_t)c;
	WRAP_INCR(len, head);
	shmcon_barrier();
	shmcon->head_out = head;
}

static int
shmcon_rr0(void)
{
	if (shmcon->tail_in == shmcon->head_in) {
		return 0;
	}
	return 1;
}

static int
shmcon_rd0(void)
{
	int c;
	uint32_t tail = shmcon->tail_in;
	uint32_t len = shmcon->buf_len[CBUF_IN];

	c = shmbuf[CBUF_IN][tail];
	WRAP_INCR(len, tail);
	shmcon_barrier();
	shmcon->tail_in = tail;
	return c;
}

static void
shmcon_init(void)
{
	DTEntry                         entry;
	uintptr_t                       *reg_prop;
	volatile struct shm_buffer_info *end;
	size_t                          i, header_size;
	unsigned int                    size;
	vm_offset_t                     pa_panic_base, panic_size, va_buffer_base, va_buffer_end;

	if (kSuccess != DTLookupEntry(0, "pram", &entry)) {
		return;
	}

	if (kSuccess != DTGetProperty(entry, "reg", (void **)&reg_prop, &size)) {
		return;
	}

	pa_panic_base = reg_prop[0];
	panic_size = reg_prop[1];

	shmcon = (struct shmcon_header *)ml_map_high_window(pa_panic_base, panic_size);
	header_size = sizeof(*shmcon) + (NUM_CHILDREN * sizeof(shmcon->child[0]));
	va_buffer_base = ROUNDUP((uintptr_t)(shmcon) + header_size, CPU_CACHELINE_SIZE);
	va_buffer_end  = (uintptr_t)shmcon + panic_size - (sizeof(*end));

	if ((shmcon->magic == SHMCON_MAGIC) && (shmcon->version == SHMCON_VERSION)) {
		vm_offset_t pa_buffer_base, pa_buffer_end;

		pa_buffer_base = ml_vtophys(va_buffer_base);
		pa_buffer_end  = ml_vtophys(va_buffer_end);

		/* Resume previous console session */
		for (i = 0; i < 2; i++) {
			vm_offset_t pa_buf;
			uint32_t len;

			pa_buf = (uintptr_t)shmcon->buf_paddr[i];
			len = shmcon->buf_len[i];
			/* Validate buffers */
			if ((pa_buf < pa_buffer_base) ||
			    (pa_buf >= pa_buffer_end) ||
			    ((pa_buf + len) > pa_buffer_end) ||
			    (shmcon->midx[i] >= len) ||     /* Index out of bounds */
			    (shmcon->sidx[i] >= len) ||
			    (pa_buf != ROUNDUP(pa_buf, CPU_CACHELINE_SIZE)) ||     /* Unaligned pa_buffer */
			    (len < 1024) ||
			    (len > (pa_buffer_end - pa_buffer_base)) ||
			    (shmcon->children != NUM_CHILDREN)) {
				goto validation_failure;
			}
			/* Compute the VA offset of the buffer */
			shmbuf[i] = (uint8_t *)(uintptr_t)shmcon + ((uintptr_t)pa_buf - (uintptr_t)pa_panic_base);
		}
		/* Check that buffers don't overlap */
		if ((uintptr_t)shmbuf[0] < (uintptr_t)shmbuf[1]) {
			if ((uintptr_t)(shmbuf[0] + shmcon->buf_len[0]) > (uintptr_t)shmbuf[1]) {
				goto validation_failure;
			}
		} else {
			if ((uintptr_t)(shmbuf[1] + shmcon->buf_len[1]) > (uintptr_t)shmbuf[0]) {
				goto validation_failure;
			}
		}
		shmcon->tail_in = shmcon->head_in; /* Clear input buffer */
		shmcon_barrier();
	} else {
validation_failure:
		shmcon->magic = 0;
		shmcon_barrier();
		shmcon->buf_len[CBUF_IN] = (uint32_t)INBUF_SIZE;
		shmbuf[CBUF_IN]  = (uint8_t *)va_buffer_base;
		shmbuf[CBUF_OUT] = (uint8_t *)ROUNDUP(va_buffer_base + INBUF_SIZE, CPU_CACHELINE_SIZE);
		for (i = 0; i < 2; i++) {
			shmcon->midx[i] = 0;
			shmcon->sidx[i] = 0;
			shmcon->buf_paddr[i] = (uintptr_t)ml_vtophys((vm_offset_t)shmbuf[i]);
		}
		shmcon->buf_len[CBUF_OUT] = (uint32_t)(va_buffer_end - (uintptr_t)shmbuf[CBUF_OUT]);
		shmcon->version = SHMCON_VERSION;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-qual"
		memset((void *)shmcon->name, ' ', sizeof(shmcon->name));
		memcpy((void *)shmcon->name, SHMCON_NAME, MIN(sizeof(shmcon->name), strlen(SHMCON_NAME)));
#pragma clang diagnostic pop
		for (i = 0; i < NUM_CHILDREN; i++) {
			shmcon->child[0] = 0;
		}
		shmcon_barrier();
		shmcon->magic = SHMCON_MAGIC;
	}
	end =  (volatile struct shm_buffer_info *)va_buffer_end;
	end->base = pa_panic_base;
	end->unused = 0;
	shmcon_barrier();
	end->magic = SHMCON_MAGIC;
#ifdef SHMCON_THROTTLED
	grace = gPEClockFrequencyInfo.timebase_frequency_hz;
#endif

	PE_consistent_debug_register(kDbgIdConsoleHeaderAP, pa_panic_base, panic_size);
}

SECURITY_READ_ONLY_LATE(static struct pe_serial_functions) shmcon_serial_functions =
{
	.uart_init = shmcon_init,
	.uart_set_baud_rate = shmcon_set_baud_rate,
	.tr0 = shmcon_tr0,
	.td0 = shmcon_td0,
	.rr0 = shmcon_rr0,
	.rd0 = shmcon_rd0
};

int
pe_shmcon_set_child(uint64_t paddr, uint32_t entry)
{
	if (shmcon == NULL) {
		return -1;
	}

	if (shmcon->children >= entry) {
		return -1;
	}

	shmcon->child[entry] = paddr;
	return 0;
}

#endif /* SHMCON */

/*****************************************************************************/

#ifdef DOCKFIFO_UART


// Allow a 30ms stall of wall clock time before DockFIFO starts dropping characters
#define DOCKFIFO_WR_MAX_STALL_US        (30*1000)

static uint64_t prev_dockfifo_drained_time; // Last time we've seen the DockFIFO drained by an external agent
static uint64_t prev_dockfifo_spaces;       // Previous w_stat level of the DockFIFO.
static uint32_t dockfifo_capacity;
static uint64_t dockfifo_stall_grace;

static vm_offset_t dockfifo_uart_base = 0;

//=======================
// Local funtions
//=======================

static int
dockfifo_drain_on_stall()
{
	// Called when DockFIFO runs out of spaces.
	// Check if the DockFIFO reader has stalled. If so, empty the DockFIFO ourselves.
	// Return number of bytes drained.

	if (mach_absolute_time() - prev_dockfifo_drained_time >= dockfifo_stall_grace) {
		// It's been more than DOCKFIFO_WR_MAX_STALL_US and nobody read from the FIFO
		// Drop a character.
		(void)rDOCKFIFO_R_DATA(DOCKFIFO_UART_READ, 1);
		os_atomic_inc(&prev_dockfifo_spaces, relaxed);
		return 1;
	}
	return 0;
}


static int
dockfifo_uart_tr0(void)
{
	uint32_t spaces = rDOCKFIFO_W_STAT(DOCKFIFO_UART_WRITE) & 0xffff;
	if (spaces >= dockfifo_capacity || spaces > prev_dockfifo_spaces) {
		// More spaces showed up. That can only mean someone read the FIFO.
		// Note that if the DockFIFO is empty we cannot tell if someone is listening,
		// we can only give them the benefit of the doubt.

		prev_dockfifo_drained_time = mach_absolute_time();
	}
	prev_dockfifo_spaces = spaces;

	return spaces || dockfifo_drain_on_stall();
}

static void
dockfifo_uart_td0(int c)
{
	rDOCKFIFO_W_DATA(DOCKFIFO_UART_WRITE, 1) = (unsigned)(c & 0xff);
	os_atomic_dec(&prev_dockfifo_spaces, relaxed); // After writing a byte we have one fewer space than previously expected.
}

static int
dockfifo_uart_rr0(void)
{
	return rDOCKFIFO_R_DATA(DOCKFIFO_UART_READ, 0) & 0x7f;
}

static int
dockfifo_uart_rd0(void)
{
	return (int)((rDOCKFIFO_R_DATA(DOCKFIFO_UART_READ, 1) >> 8) & 0xff);
}

static void
dockfifo_uart_init(void)
{
	nanoseconds_to_absolutetime(DOCKFIFO_WR_MAX_STALL_US * 1000, &dockfifo_stall_grace);

	// Disable autodraining of the FIFO. We now purely manage it in software.
	rDOCKFIFO_DRAIN(DOCKFIFO_UART_WRITE) = 0;

	// Empty the DockFIFO by draining it until OCCUPANCY is 0, then measure its capacity
	while (rDOCKFIFO_R_DATA(DOCKFIFO_UART_WRITE, 3) & 0x7F) {
		;
	}
	dockfifo_capacity = rDOCKFIFO_W_STAT(DOCKFIFO_UART_WRITE) & 0xffff;
}

SECURITY_READ_ONLY_LATE(static struct pe_serial_functions) dockfifo_uart_serial_functions =
{
	.uart_init = dockfifo_uart_init,
	.uart_set_baud_rate = NULL,
	.tr0 = dockfifo_uart_tr0,
	.td0 = dockfifo_uart_td0,
	.rr0 = dockfifo_uart_rr0,
	.rd0 = dockfifo_uart_rd0
};

#endif /* DOCKFIFO_UART */

/*****************************************************************************/

#ifdef DOCKCHANNEL_UART
#define DOCKCHANNEL_WR_MAX_STALL_US     (30*1000)

static vm_offset_t      dock_agent_base;
static uint32_t         max_dockchannel_drain_period;
static bool             use_sw_drain;
static uint64_t         prev_dockchannel_drained_time;  // Last time we've seen the DockChannel drained by an external agent
static uint64_t         prev_dockchannel_spaces;        // Previous w_stat level of the DockChannel.
static uint64_t         dockchannel_stall_grace;
static vm_offset_t      dockchannel_uart_base = 0;

//=======================
// Local funtions
//=======================

static int
dockchannel_drain_on_stall()
{
	// Called when DockChannel runs out of spaces.
	// Check if the DockChannel reader has stalled. If so, empty the DockChannel ourselves.
	// Return number of bytes drained.

	if ((mach_absolute_time() - prev_dockchannel_drained_time) >= dockchannel_stall_grace) {
		// It's been more than DOCKCHANEL_WR_MAX_STALL_US and nobody read from the FIFO
		// Drop a character.
		(void)rDOCKCHANNELS_DEV_RDATA1(DOCKCHANNEL_UART_CHANNEL);
		os_atomic_inc(&prev_dockchannel_spaces, relaxed);
		return 1;
	}
	return 0;
}

static int
dockchannel_uart_tr0(void)
{
	if (use_sw_drain) {
		uint32_t spaces = rDOCKCHANNELS_DEV_WSTAT(DOCKCHANNEL_UART_CHANNEL) & 0x1ff;
		if (spaces > prev_dockchannel_spaces) {
			// More spaces showed up. That can only mean someone read the FIFO.
			// Note that if the DockFIFO is empty we cannot tell if someone is listening,
			// we can only give them the benefit of the doubt.
			prev_dockchannel_drained_time = mach_absolute_time();
		}
		prev_dockchannel_spaces = spaces;

		return spaces || dockchannel_drain_on_stall();
	} else {
		// Returns spaces in dockchannel fifo
		return rDOCKCHANNELS_DEV_WSTAT(DOCKCHANNEL_UART_CHANNEL) & 0x1ff;
	}
}

static void
dockchannel_uart_td0(int c)
{
	rDOCKCHANNELS_DEV_WDATA1(DOCKCHANNEL_UART_CHANNEL) = (unsigned)(c & 0xff);
	if (use_sw_drain) {
		os_atomic_dec(&prev_dockchannel_spaces, relaxed); // After writing a byte we have one fewer space than previously expected.
	}
}

static int
dockchannel_uart_rr0(void)
{
	return rDOCKCHANNELS_DEV_RDATA0(DOCKCHANNEL_UART_CHANNEL) & 0x7f;
}

static int
dockchannel_uart_rd0(void)
{
	return (int)((rDOCKCHANNELS_DEV_RDATA1(DOCKCHANNEL_UART_CHANNEL) >> 8) & 0xff);
}

static void
dockchannel_uart_clear_intr(void)
{
	rDOCKCHANNELS_AGENT_AP_INTR_CTRL &= ~(0x3);
	rDOCKCHANNELS_AGENT_AP_INTR_STATUS |= 0x3;
	rDOCKCHANNELS_AGENT_AP_ERR_INTR_CTRL &= ~(0x3);
	rDOCKCHANNELS_AGENT_AP_ERR_INTR_STATUS |= 0x3;
}

static void
dockchannel_uart_init(void)
{
	if (use_sw_drain) {
		nanoseconds_to_absolutetime(DOCKCHANNEL_WR_MAX_STALL_US * NSEC_PER_USEC, &dockchannel_stall_grace);
	}

	// Clear all interrupt enable and status bits
	dockchannel_uart_clear_intr();

	// Setup DRAIN timer
	rDOCKCHANNELS_DEV_DRAIN_CFG(DOCKCHANNEL_UART_CHANNEL) = max_dockchannel_drain_period;

	// Drain timer doesn't get loaded with value from drain period register if fifo
	// is already full. Drop a character from the fifo.
	rDOCKCHANNELS_DOCK_RDATA1(DOCKCHANNEL_UART_CHANNEL);
}

SECURITY_READ_ONLY_LATE(static struct pe_serial_functions) dockchannel_uart_serial_functions =
{
	.uart_init = dockchannel_uart_init,
	.uart_set_baud_rate = NULL,
	.tr0 = dockchannel_uart_tr0,
	.td0 = dockchannel_uart_td0,
	.rr0 = dockchannel_uart_rr0,
	.rd0 = dockchannel_uart_rd0
};

#endif /* DOCKCHANNEL_UART */

/****************************************************************************/
#ifdef  PI3_UART
vm_offset_t pi3_gpio_base_vaddr = 0;
vm_offset_t pi3_aux_base_vaddr = 0;
static int
pi3_uart_tr0(void)
{
	return (int) BCM2837_GET32(BCM2837_AUX_MU_LSR_REG_V) & 0x20;
}

static void
pi3_uart_td0(int c)
{
	BCM2837_PUT32(BCM2837_AUX_MU_IO_REG_V, (uint32_t) c);
}

static int
pi3_uart_rr0(void)
{
	return (int) BCM2837_GET32(BCM2837_AUX_MU_LSR_REG_V) & 0x01;
}

static int
pi3_uart_rd0(void)
{
	return (int) BCM2837_GET32(BCM2837_AUX_MU_IO_REG_V) & 0xff;
}

static void
pi3_uart_init(void)
{
	// Scratch variable
	uint32_t i;

	// Reset mini uart registers
	BCM2837_PUT32(BCM2837_AUX_ENABLES_V, 1);
	BCM2837_PUT32(BCM2837_AUX_MU_CNTL_REG_V, 0);
	BCM2837_PUT32(BCM2837_AUX_MU_LCR_REG_V, 3);
	BCM2837_PUT32(BCM2837_AUX_MU_MCR_REG_V, 0);
	BCM2837_PUT32(BCM2837_AUX_MU_IER_REG_V, 0);
	BCM2837_PUT32(BCM2837_AUX_MU_IIR_REG_V, 0xC6);
	BCM2837_PUT32(BCM2837_AUX_MU_BAUD_REG_V, 270);

	i = BCM2837_FSEL_REG(14);
	// Configure GPIOs 14 & 15 for alternate function 5
	i &= ~(BCM2837_FSEL_MASK(14));
	i |= (BCM2837_FSEL_ALT5 << BCM2837_FSEL_OFFS(14));
	i &= ~(BCM2837_FSEL_MASK(15));
	i |= (BCM2837_FSEL_ALT5 << BCM2837_FSEL_OFFS(15));

	BCM2837_PUT32(BCM2837_FSEL_REG(14), i);

	BCM2837_PUT32(BCM2837_GPPUD_V, 0);

	// Barrier before AP spinning for 150 cycles
	__builtin_arm_isb(ISB_SY);

	for (i = 0; i < 150; i++) {
		asm volatile ("add x0, x0, xzr");
	}

	__builtin_arm_isb(ISB_SY);

	BCM2837_PUT32(BCM2837_GPPUDCLK0_V, (1 << 14) | (1 << 15));

	__builtin_arm_isb(ISB_SY);

	for (i = 0; i < 150; i++) {
		asm volatile ("add x0, x0, xzr");
	}

	__builtin_arm_isb(ISB_SY);

	BCM2837_PUT32(BCM2837_GPPUDCLK0_V, 0);

	BCM2837_PUT32(BCM2837_AUX_MU_CNTL_REG_V, 3);
}

SECURITY_READ_ONLY_LATE(static struct pe_serial_functions) pi3_uart_serial_functions =
{
	.uart_init = pi3_uart_init,
	.uart_set_baud_rate = NULL,
	.tr0 = pi3_uart_tr0,
	.td0 = pi3_uart_td0,
	.rr0 = pi3_uart_rr0,
	.rd0 = pi3_uart_rd0
};

#endif /* PI3_UART */
/*****************************************************************************/

static void
register_serial_functions(struct pe_serial_functions *fns)
{
	fns->next = gPESF;
	gPESF = fns;
}

int
serial_init(void)
{
	DTEntry         entryP = NULL;
	uint32_t        prop_size;
	vm_offset_t     soc_base;
	uintptr_t       *reg_prop;
	uint32_t        *prop_value __unused = NULL;
	char            *serial_compat __unused = 0;
	uint32_t        dccmode;

	struct pe_serial_functions *fns = gPESF;

	if (uart_initted) {
		while (fns != NULL) {
			fns->uart_init();
			fns = fns->next;
		}
		kprintf("reinit serial\n");
		return 1;
	}

	dccmode = 0;
	if (PE_parse_boot_argn("dcc", &dccmode, sizeof(dccmode))) {
		register_serial_functions(&dcc_serial_functions);
	}
#ifdef SHMCON
	uint32_t jconmode = 0;
	if (PE_parse_boot_argn("jcon", &jconmode, sizeof jconmode)) {
		register_serial_functions(&shmcon_serial_functions);
	}
#endif /* SHMCON */

	soc_base = pe_arm_get_soc_base_phys();

	if (soc_base == 0) {
		return 0;
	}

#ifdef PI3_UART
	if (DTFindEntry("name", "gpio", &entryP) == kSuccess) {
		DTGetProperty(entryP, "reg", (void **)&reg_prop, &prop_size);
		pi3_gpio_base_vaddr = ml_io_map(soc_base + *reg_prop, *(reg_prop + 1));
	}
	if (DTFindEntry("name", "aux", &entryP) == kSuccess) {
		DTGetProperty(entryP, "reg", (void **)&reg_prop, &prop_size);
		pi3_aux_base_vaddr = ml_io_map(soc_base + *reg_prop, *(reg_prop + 1));
	}
	if ((pi3_gpio_base_vaddr != 0) && (pi3_aux_base_vaddr != 0)) {
		register_serial_functions(&pi3_uart_serial_functions);
	}
#endif /* PI3_UART */

#ifdef DOCKFIFO_UART
	uint32_t no_dockfifo_uart = 0;
	PE_parse_boot_argn("no-dockfifo-uart", &no_dockfifo_uart, sizeof(no_dockfifo_uart));
	if (no_dockfifo_uart == 0) {
		if (DTFindEntry("name", "dockfifo-uart", &entryP) == kSuccess) {
			DTGetProperty(entryP, "reg", (void **)&reg_prop, &prop_size);
			dockfifo_uart_base = ml_io_map(soc_base + *reg_prop, *(reg_prop + 1));
			register_serial_functions(&dockfifo_uart_serial_functions);
		}
	}
#endif /* DOCKFIFO_UART */

#ifdef DOCKCHANNEL_UART
	uint32_t no_dockchannel_uart = 0;
	if (DTFindEntry("name", "dockchannel-uart", &entryP) == kSuccess) {
		DTGetProperty(entryP, "reg", (void **)&reg_prop, &prop_size);
		// Should be two reg entries
		if (prop_size / sizeof(uintptr_t) != 4) {
			panic("Malformed dockchannel-uart property");
		}
		dockchannel_uart_base = ml_io_map(soc_base + *reg_prop, *(reg_prop + 1));
		dock_agent_base = ml_io_map(soc_base + *(reg_prop + 2), *(reg_prop + 3));
		PE_parse_boot_argn("no-dockfifo-uart", &no_dockchannel_uart, sizeof(no_dockchannel_uart));
		// Keep the old name for boot-arg
		if (no_dockchannel_uart == 0) {
			register_serial_functions(&dockchannel_uart_serial_functions);
			DTGetProperty(entryP, "max-aop-clk", (void **)&prop_value, &prop_size);
			max_dockchannel_drain_period = (uint32_t)((prop_value)?  (*prop_value * 0.03) : DOCKCHANNEL_DRAIN_PERIOD);
			DTGetProperty(entryP, "enable-sw-drain", (void **)&prop_value, &prop_size);
			use_sw_drain = (prop_value)?  *prop_value : 0;
		} else {
			dockchannel_uart_clear_intr();
		}
		// If no dockchannel-uart is found in the device tree, fall back
		// to looking for the traditional UART serial console.
	}

#endif /* DOCKCHANNEL_UART */

	/*
	 * The boot serial port should have a property named "boot-console".
	 * If we don't find it there, look for "uart0" and "uart1".
	 */

	if (DTFindEntry("boot-console", NULL, &entryP) == kSuccess) {
		DTGetProperty(entryP, "reg", (void **)&reg_prop, &prop_size);
		uart_base = ml_io_map(soc_base + *reg_prop, *(reg_prop + 1));
		if (serial_compat == 0) {
			DTGetProperty(entryP, "compatible", (void **)&serial_compat, &prop_size);
		}
	} else if (DTFindEntry("name", "uart0", &entryP) == kSuccess) {
		DTGetProperty(entryP, "reg", (void **)&reg_prop, &prop_size);
		uart_base = ml_io_map(soc_base + *reg_prop, *(reg_prop + 1));
		if (serial_compat == 0) {
			DTGetProperty(entryP, "compatible", (void **)&serial_compat, &prop_size);
		}
	} else if (DTFindEntry("name", "uart1", &entryP) == kSuccess) {
		DTGetProperty(entryP, "reg", (void **)&reg_prop, &prop_size);
		uart_base = ml_io_map(soc_base + *reg_prop, *(reg_prop + 1));
		if (serial_compat == 0) {
			DTGetProperty(entryP, "compatible", (void **)&serial_compat, &prop_size);
		}
	}
#ifdef  S3CUART
	if (NULL != entryP) {
		DTGetProperty(entryP, "pclk", (void **)&prop_value, &prop_size);
		if (prop_value) {
			dt_pclk = *prop_value;
		}

		prop_value = NULL;
		DTGetProperty(entryP, "sampling", (void **)&prop_value, &prop_size);
		if (prop_value) {
			dt_sampling = *prop_value;
		}

		prop_value = NULL;
		DTGetProperty(entryP, "ubrdiv", (void **)&prop_value, &prop_size);
		if (prop_value) {
			dt_ubrdiv = *prop_value;
		}
	}
	if (!strcmp(serial_compat, "uart,16550")) {
		register_serial_functions(&ln2410_serial_functions);
	} else if (!strcmp(serial_compat, "uart-16550")) {
		register_serial_functions(&ln2410_serial_functions);
	} else if (!strcmp(serial_compat, "uart,s5i3000")) {
		register_serial_functions(&ln2410_serial_functions);
	} else if (!strcmp(serial_compat, "uart-1,samsung")) {
		register_serial_functions(&ln2410_serial_functions);
	}
#endif /* S3CUART */

	if (gPESF == NULL) {
		return 0;
	}

	fns = gPESF;
	while (fns != NULL) {
		fns->uart_init();
		fns = fns->next;
	}

	uart_initted = 1;

	return 1;
}

void
uart_putc(char c)
{
	struct pe_serial_functions *fns = gPESF;
	while (fns != NULL) {
		while (!fns->tr0()) {
			;               /* Wait until THR is empty. */
		}
		fns->td0(c);
		fns = fns->next;
	}
}

int
uart_getc(void)
{                               /* returns -1 if no data available */
	struct pe_serial_functions *fns = gPESF;
	while (fns != NULL) {
		if (fns->rr0()) {
			return fns->rd0();
		}
		fns = fns->next;
	}
	return -1;
}
