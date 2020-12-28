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

#ifdef __x86_64__
#include <i386/mp.h>
#include <i386/cpu_data.h>
#include <i386/bit_routines.h>
#include <i386/machine_cpu.h>
#include <i386/machine_routines.h>
#include <i386/misc_protos.h>
#include <i386/serial_io.h>
#endif /* __x86_64__ */

#include <libkern/OSAtomic.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <console/video_console.h>
#include <console/serial_protos.h>
#include <kern/kalloc.h>
#include <kern/thread.h>
#include <kern/cpu_data.h>
#include <libkern/section_keywords.h>

#if __arm__ || __arm64__
#include <machine/machine_routines.h>
#include <arm/cpu_data_internal.h>
#endif

#ifdef CONFIG_XNUPOST
#include <tests/xnupost.h>
kern_return_t console_serial_test(void);
kern_return_t console_serial_alloc_rel_tests(void);
kern_return_t console_serial_parallel_log_tests(void);
#define MAX_CPU_SLOTS (MAX_CPUS + 2)
#endif

#ifndef MAX_CPU_SLOTS
#define MAX_CPU_SLOTS (MAX_CPUS)
#endif

static struct {
	char * buffer;
	int len;
	int used;
	char * write_ptr;
	char * read_ptr;
	decl_simple_lock_data(, read_lock);
	decl_simple_lock_data(, write_lock);
} console_ring;

hw_lock_data_t cnputc_lock;
static volatile uint32_t console_output = 0;

/*
 * New allocation mechanism for console buffers
 * Total allocation: 1 * PAGE_SIZE
 * - Each cpu gets CPU_CONS_BUF_SIZE buffer
 * - Kernel wide console ring gets PAGE_SIZE - MAX_CPU_SLOTS * CPU_CONS_BUF_SIZE
 *
 * At the return from console_init() the memory is setup as follows:
 *  +----------------------------+-------------+-------------+-------------+-------------+
 *  |console ring buffer---------|f2eec075-----|f2eec075-----|f2eec075-----|f2eec075-----|
 *  +----------------------------+-------------+-------------+-------------+-------------+
 * Each cpu allocation will find the first (f2eec075) and use that buffer.
 *
 */

#define CPU_CONS_BUF_SIZE 256
#define CPU_BUF_FREE_HEX 0xf2eec075

#define KERN_CONSOLE_BUF_SIZE vm_map_round_page(CPU_CONS_BUF_SIZE *(MAX_CPU_SLOTS + 1), PAGE_SIZE - 1)
#define KERN_CONSOLE_RING_SIZE (KERN_CONSOLE_BUF_SIZE - (CPU_CONS_BUF_SIZE * MAX_CPU_SLOTS))

/*
 * A serial line running at 115200 bps can output ~11.5 characters per millisecond.
 * Synchronous serial logging with preemption+interrupts disabled fundamentally prevents us
 * from hitting expected scheduling deadlines, but we can at least tone it down a bit.
 *
 * TODO: IOLog should use asynchronous serial logging instead of the synchronous serial console. (26555148)
 *
 * Keep interrupt disabled periods shorter than 1ms
 */
#define MAX_INT_DISABLED_FLUSH_SIZE 8
#define MAX_TOTAL_FLUSH_SIZE (MAX(2, MAX_CPU_SLOTS) * CPU_CONS_BUF_SIZE)

typedef struct console_buf {
	char * buf_base;
	char * buf_end;
	char * buf_ptr;
#define CPU_BUFFER_LEN (CPU_CONS_BUF_SIZE - 3 * (sizeof(char *)))
	char buf[CPU_BUFFER_LEN];
} console_buf_t;

extern int serial_getc(void);
extern void serial_putc(char);

static void _serial_putc(int, int, int);

SECURITY_READ_ONLY_EARLY(struct console_ops) cons_ops[] = {
	{
		.putc = _serial_putc, .getc = _serial_getc,
	},
	{
		.putc = vcputc, .getc = vcgetc,
	},
};

SECURITY_READ_ONLY_EARLY(uint32_t) nconsops = (sizeof cons_ops / sizeof cons_ops[0]);

uint32_t cons_ops_index = VC_CONS_OPS;

#if defined(__x86_64__) || defined(__arm__)
// NMI static variables
#define NMI_STRING_SIZE 32
char nmi_string[NMI_STRING_SIZE] = "afDIGHr84A84jh19Kphgp428DNPdnapq";
static int nmi_counter           = 0;
#endif /* __arm__ */

static bool console_suspended = false;

/* Wrapper for ml_set_interrupts_enabled */
static void
console_restore_interrupts_state(boolean_t state)
{
#if INTERRUPT_MASKED_DEBUG
	/*
	 * Serial console holds interrupts disabled for far too long
	 * and would trip the spin-debugger.  If we are about to reenable
	 * interrupts then clear the timer and avoid panicking on the delay.
	 * Otherwise, let the code that printed with interrupt disabled
	 * take the panic when it reenables interrupts.
	 * Hopefully one day this is fixed so that this workaround is unnecessary.
	 */
	if (state == TRUE) {
		ml_spin_debug_clear_self();
	}
#endif /* INTERRUPT_MASKED_DEBUG */
	ml_set_interrupts_enabled(state);
}

static void
console_ring_lock_init(void)
{
	simple_lock_init(&console_ring.read_lock, 0);
	simple_lock_init(&console_ring.write_lock, 0);
}

void
console_init(void)
{
	int ret, i;
	uint32_t * p;

	if (!OSCompareAndSwap(0, KERN_CONSOLE_RING_SIZE, (UInt32 *)&console_ring.len)) {
		return;
	}

	assert(console_ring.len > 0);

	ret = kmem_alloc(kernel_map, (vm_offset_t *)&console_ring.buffer, KERN_CONSOLE_BUF_SIZE, VM_KERN_MEMORY_OSFMK);
	if (ret != KERN_SUCCESS) {
		panic("console_ring_init() failed to allocate ring buffer, error %d\n", ret);
	}

	/* setup memory for per cpu console buffers */
	for (i = 0; i < MAX_CPU_SLOTS; i++) {
		p  = (uint32_t *)((uintptr_t)console_ring.buffer + console_ring.len + (i * sizeof(console_buf_t)));
		*p = CPU_BUF_FREE_HEX;
	}

	console_ring.used      = 0;
	console_ring.read_ptr  = console_ring.buffer;
	console_ring.write_ptr = console_ring.buffer;
	console_ring_lock_init();
	hw_lock_init(&cnputc_lock);
}

void *
console_cpu_alloc(__unused boolean_t boot_processor)
{
	console_buf_t * cbp;
	int i;
	uint32_t * p = NULL;

	console_init();
	assert(console_ring.buffer != NULL);

	/* select the next slot from the per cpu buffers at end of console_ring.buffer */
	for (i = 0; i < MAX_CPU_SLOTS; i++) {
		p = (uint32_t *)((uintptr_t)console_ring.buffer + console_ring.len + (i * sizeof(console_buf_t)));
		if (OSCompareAndSwap(CPU_BUF_FREE_HEX, 0, (UInt32 *)p)) {
			break;
		}
	}
	assert(i < MAX_CPU_SLOTS);

	cbp = (console_buf_t *)(uintptr_t)p;
	if ((uintptr_t)cbp >= (uintptr_t)console_ring.buffer + KERN_CONSOLE_BUF_SIZE) {
		printf("console_cpu_alloc() failed to allocate cpu buffer\n");
		return NULL;
	}

	cbp->buf_base = (char *)&cbp->buf;
	cbp->buf_ptr  = cbp->buf_base;
	cbp->buf_end = cbp->buf_base + CPU_BUFFER_LEN;
	return (void *)cbp;
}

void
console_cpu_free(void * buf)
{
	assert((uintptr_t)buf > (uintptr_t)console_ring.buffer);
	assert((uintptr_t)buf < (uintptr_t)console_ring.buffer + KERN_CONSOLE_BUF_SIZE);
	if (buf != NULL) {
		*(uint32_t *)buf = CPU_BUF_FREE_HEX;
	}
}

static inline int
console_ring_space(void)
{
	return console_ring.len - console_ring.used;
}

static boolean_t
console_ring_put(char ch)
{
	if (console_ring.used < console_ring.len) {
		console_ring.used++;
		*console_ring.write_ptr++ = ch;
		if (console_ring.write_ptr - console_ring.buffer == console_ring.len) {
			console_ring.write_ptr = console_ring.buffer;
		}
		return TRUE;
	} else {
		return FALSE;
	}
}

static inline boolean_t
cpu_buffer_put(console_buf_t * cbp, char ch)
{
	if (ch != '\0' && cbp->buf_ptr < cbp->buf_end) {
		*(cbp->buf_ptr++) = ch;
		return TRUE;
	} else {
		return FALSE;
	}
}

static inline int
cpu_buffer_size(console_buf_t * cbp)
{
	return (int)(cbp->buf_ptr - cbp->buf_base);
}

static inline void
_cnputs(char * c, int size)
{
	/* The console device output routines are assumed to be
	 * non-reentrant.
	 */
#ifdef __x86_64__
	uint32_t lock_timeout_ticks = UINT32_MAX;
#else
	uint32_t lock_timeout_ticks = LockTimeOut * 2; // 250ms is not enough, 500 is just right
#endif

	mp_disable_preemption();
	if (!hw_lock_to(&cnputc_lock, lock_timeout_ticks, LCK_GRP_NULL)) {
		/* If we timed out on the lock, and we're in the debugger,
		 * copy lock data for debugging and break the lock.
		 */
		hw_lock_data_t _shadow_lock;
		memcpy(&_shadow_lock, &cnputc_lock, sizeof(cnputc_lock));
		if (kernel_debugger_entry_count) {
			/* Since hw_lock_to takes a pre-emption count...*/
			mp_enable_preemption();
			hw_lock_init(&cnputc_lock);
			hw_lock_lock(&cnputc_lock, LCK_GRP_NULL);
		} else {
			panic("Lock acquire timeout in _cnputs() lock=%p, lock owner thread=0x%lx, current_thread: %p\n", &_shadow_lock,
			    _shadow_lock.lock_data, current_thread());
		}
	}

	while (size-- > 0) {
		if (*c == '\n') {
			cons_ops[cons_ops_index].putc(0, 0, '\r');
		}
		cons_ops[cons_ops_index].putc(0, 0, *c);
		c++;
	}

	hw_lock_unlock(&cnputc_lock);
	mp_enable_preemption();
}

void
cnputc_unbuffered(char c)
{
	_cnputs(&c, 1);
}


void
cnputcusr(char c)
{
	cnputsusr(&c, 1);
}

void
cnputsusr(char *s, int size)
{
	if (size > 1) {
		console_write(s, size);
		return;
	}

	boolean_t state;

	/* Spin (with pre-emption enabled) waiting for console_ring_try_empty()
	 * to complete output. There is a small window here where we could
	 * end up with a stale value of console_output, but it's unlikely,
	 * and _cnputs(), which outputs to the console device, is internally
	 * synchronized. There's something of a conflict between the
	 * character-at-a-time (with pre-emption enabled) unbuffered
	 * output model here, and the buffered output from cnputc(),
	 * whose consumers include printf() ( which outputs a sequence
	 * with pre-emption disabled, and should be safe to call with
	 * interrupts off); we don't want to disable pre-emption indefinitely
	 * here, and spinlocks and mutexes are inappropriate.
	 */
	while (console_output != 0) {
		delay(1);
	}

	/*
	 * We disable interrupts to avoid issues caused by rendevous IPIs
	 * and an interruptible core holding the lock while an uninterruptible
	 * core wants it.  Stackshot is the prime example of this.
	 */
	state = ml_set_interrupts_enabled(FALSE);
	_cnputs(s, 1);
	console_restore_interrupts_state(state);
}

static void
console_ring_try_empty(void)
{
#ifdef __x86_64__
	boolean_t handle_tlb_flushes = (ml_get_interrupts_enabled() == FALSE);
#endif /* __x86_64__ */

	int nchars_out       = 0;
	int total_chars_out  = 0;
	int size_before_wrap = 0;

	do {
#ifdef __x86_64__
		if (handle_tlb_flushes) {
			handle_pending_TLB_flushes();
		}
#endif /* __x86_64__ */

		/*
		 * Try to get the read lock on the ring buffer to empty it.
		 * If this fails someone else is already emptying...
		 */
		if (!simple_lock_try(&console_ring.read_lock, LCK_GRP_NULL)) {
			/*
			 * If multiple cores are spinning trying to empty the buffer,
			 * we may suffer lock starvation (get the read lock, but
			 * never the write lock, with other cores unable to get the
			 * read lock).  As a result, insert a delay on failure, to
			 * let other cores have a turn.
			 */
			delay(1);
			return;
		}

		boolean_t state = ml_set_interrupts_enabled(FALSE);

		/* Indicate that we're in the process of writing a block of data to the console. */
		os_atomic_inc(&console_output, relaxed);

		simple_lock_try_lock_loop(&console_ring.write_lock, LCK_GRP_NULL);

		/* try small chunk at a time, so we allow writes from other cpus into the buffer */
		nchars_out = MIN(console_ring.used, MAX_INT_DISABLED_FLUSH_SIZE);

		/* account for data to be read before wrap around */
		size_before_wrap = (int)((console_ring.buffer + console_ring.len) - console_ring.read_ptr);
		if (nchars_out > size_before_wrap) {
			nchars_out = size_before_wrap;
		}

		if (nchars_out > 0) {
			_cnputs(console_ring.read_ptr, nchars_out);
			console_ring.read_ptr =
			    console_ring.buffer + ((console_ring.read_ptr - console_ring.buffer + nchars_out) % console_ring.len);
			console_ring.used -= nchars_out;
			total_chars_out += nchars_out;
		}

		simple_unlock(&console_ring.write_lock);

		os_atomic_dec(&console_output, relaxed);

		simple_unlock(&console_ring.read_lock);

		console_restore_interrupts_state(state);

		/*
		 * In case we end up being the console drain thread
		 * for far too long, break out. Except in panic/suspend cases
		 * where we should clear out full buffer.
		 */
		if (!kernel_debugger_entry_count && !console_suspended && (total_chars_out >= MAX_TOTAL_FLUSH_SIZE)) {
			break;
		}
	} while (nchars_out > 0);
}


void
console_suspend()
{
	console_suspended = true;
	console_ring_try_empty();
}

void
console_resume()
{
	console_suspended = false;
}

void
console_write(char * str, int size)
{
	console_init();
	int chunk_size = size;
	int i          = 0;

	if (size > console_ring.len) {
		chunk_size = CPU_CONS_BUF_SIZE;
	}

	while (size > 0) {
		boolean_t state = ml_set_interrupts_enabled(FALSE);

		simple_lock_try_lock_loop(&console_ring.write_lock, LCK_GRP_NULL);
		while (chunk_size > console_ring_space()) {
			simple_unlock(&console_ring.write_lock);
			console_restore_interrupts_state(state);

			console_ring_try_empty();

			state = ml_set_interrupts_enabled(FALSE);
			simple_lock_try_lock_loop(&console_ring.write_lock, LCK_GRP_NULL);
		}

		for (i = 0; i < chunk_size; i++) {
			console_ring_put(str[i]);
		}

		str = &str[i];
		size -= chunk_size;
		simple_unlock(&console_ring.write_lock);
		console_restore_interrupts_state(state);
	}

	console_ring_try_empty();
}

void
cnputc(char c)
{
	console_buf_t * cbp;
	cpu_data_t * cpu_data_p;
	boolean_t state;
	boolean_t needs_print = TRUE;
	char * cp;

restart:
	mp_disable_preemption();
	cpu_data_p = current_cpu_datap();
	cbp = (console_buf_t *)cpu_data_p->cpu_console_buf;
	if (console_suspended || cbp == NULL) {
		mp_enable_preemption();
		/* Put directly if console ring is not initialized or we're heading into suspend */
		_cnputs(&c, 1);
		return;
	}

#ifndef __x86_64__
	/* Is there a panic backtrace going on? */
	if (cpu_data_p->PAB_active) {
		/* If another processor was in the process of emptying the
		 * console ring buffer when it received the panic backtrace
		 * signal, that processor will be spinning in DebugXCall()
		 * waiting for the panicking processor to finish printing
		 * the backtrace. But panicking processor will never
		 * be able to obtain the ring buffer lock since it is
		 * owned by a processor that's spinning in DebugXCall().
		 * Blow away any locks that other processors may have on
		 * the console ring buffer so that the backtrace can
		 * complete.
		 */
		console_ring_lock_init();
	}
#endif /* __x86_64__ */

	state = ml_set_interrupts_enabled(FALSE);

	/*
	 * add to stack buf
	 * If the cpu buffer is full, we'll flush, then try
	 * another put.  If it fails a second time... screw
	 * it.
	 */
	if (needs_print && !cpu_buffer_put(cbp, c)) {
		simple_lock_try_lock_loop(&console_ring.write_lock, LCK_GRP_NULL);

		if (cpu_buffer_size(cbp) > console_ring_space()) {
			simple_unlock(&console_ring.write_lock);
			console_restore_interrupts_state(state);
			mp_enable_preemption();

			console_ring_try_empty();
			goto restart;
		}

		for (cp = cbp->buf_base; cp < cbp->buf_ptr; cp++) {
			console_ring_put(*cp);
		}
		cbp->buf_ptr = cbp->buf_base;
		simple_unlock(&console_ring.write_lock);

		cpu_buffer_put(cbp, c);
	}

	needs_print = FALSE;

	if (c != '\n') {
		console_restore_interrupts_state(state);
		mp_enable_preemption();
		return;
	}

	/* We printed a newline, time to flush the CPU buffer to the global buffer */
	simple_lock_try_lock_loop(&console_ring.write_lock, LCK_GRP_NULL);

	/*
	 * Is there enough space in the shared ring buffer?
	 * Try to empty if not.
	 * Note, we want the entire local buffer to fit to
	 * avoid another cpu interjecting.
	 */

	if (cpu_buffer_size(cbp) > console_ring_space()) {
		simple_unlock(&console_ring.write_lock);
		console_restore_interrupts_state(state);
		mp_enable_preemption();

		console_ring_try_empty();

		goto restart;
	}

	for (cp = cbp->buf_base; cp < cbp->buf_ptr; cp++) {
		console_ring_put(*cp);
	}

	cbp->buf_ptr = cbp->buf_base;
	simple_unlock(&console_ring.write_lock);

	console_restore_interrupts_state(state);
	mp_enable_preemption();

	console_ring_try_empty();

	return;
}

int
_serial_getc(__unused int a, __unused int b, boolean_t wait, __unused boolean_t raw)
{
	int c;
	do {
		c = serial_getc();
	} while (wait && c < 0);

#if defined(__x86_64__) || defined(__arm__)
	// Check for the NMI string
	if (c == nmi_string[nmi_counter]) {
		nmi_counter++;
		if (nmi_counter == NMI_STRING_SIZE) {
			// We've got the NMI string, now do an NMI
			Debugger("Automatic NMI");
			nmi_counter = 0;
			return '\n';
		}
	} else if (c != -1) {
		nmi_counter = 0;
	}
#endif

	return c;
}

static void
_serial_putc(__unused int a, __unused int b, int c)
{
	serial_putc(c);
}

int
cngetc(void)
{
	return cons_ops[cons_ops_index].getc(0, 0, TRUE, FALSE);
}

int
cnmaygetc(void)
{
	return cons_ops[cons_ops_index].getc(0, 0, FALSE, FALSE);
}

int
vcgetc(__unused int l, __unused int u, __unused boolean_t wait, __unused boolean_t raw)
{
	char c;

	if (0 == PE_stub_poll_input(0, &c)) {
		return c;
	} else {
		return 0;
	}
}

#ifdef CONFIG_XNUPOST
static uint32_t cons_test_ops_count = 0;

/*
 * Try to do multiple cpu buffer allocs and free and intentionally
 * allow for pre-emption.
 */
static void
alloc_free_func(void * arg, wait_result_t wres __unused)
{
	console_buf_t * cbp = NULL;
	int count           = (int)arg;

	T_LOG("Doing %d iterations of console cpu alloc and free.", count);

	while (count-- > 0) {
		os_atomic_inc(&cons_test_ops_count, relaxed);
		cbp = (console_buf_t *)console_cpu_alloc(0);
		if (cbp == NULL) {
			T_ASSERT_NOTNULL(cbp, "cpu allocation failed");
		}
		console_cpu_free(cbp);
		cbp = NULL;
		/* give chance to another thread to come in */
		delay(10);
	}
}

/*
 * Log to console by multiple methods - printf, unbuffered write, console_write()
 */
static void
log_to_console_func(void * arg __unused, wait_result_t wres __unused)
{
	uint64_t thread_id = current_thread()->thread_id;
	char somedata[10] = "123456789";
	for (int i = 0; i < 26; i++) {
		os_atomic_inc(&cons_test_ops_count, relaxed);
		printf(" thid: %llu printf iteration %d\n", thread_id, i);
		cnputc_unbuffered((char)('A' + i));
		cnputc_unbuffered('\n');
		console_write((char *)somedata, sizeof(somedata));
		delay(10);
	}
	printf("finished the log_to_console_func operations\n\n");
}

kern_return_t
console_serial_parallel_log_tests(void)
{
	thread_t thread;
	kern_return_t kr;
	cons_test_ops_count = 0;

	kr = kernel_thread_start(log_to_console_func, NULL, &thread);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "kernel_thread_start returned successfully");

	delay(100);

	log_to_console_func(NULL, 0);

	/* wait until other thread has also finished */
	while (cons_test_ops_count < 52) {
		delay(1000);
	}

	thread_deallocate(thread);
	T_LOG("parallel_logging tests is now complete. From this point forward we expect full lines\n");
	return KERN_SUCCESS;
}

kern_return_t
console_serial_alloc_rel_tests(void)
{
	unsigned long i, free_buf_count = 0;
	uint32_t * p;
	console_buf_t * cbp;
	thread_t thread;
	kern_return_t kr;

	T_LOG("doing alloc/release tests");

	for (i = 0; i < MAX_CPU_SLOTS; i++) {
		p   = (uint32_t *)((uintptr_t)console_ring.buffer + console_ring.len + (i * sizeof(console_buf_t)));
		cbp = (console_buf_t *)(void *)p;
		/* p should either be allocated cpu buffer or have CPU_BUF_FREE_HEX in it */
		T_ASSERT(*p == CPU_BUF_FREE_HEX || cbp->buf_base == &cbp->buf[0], "");
		if (*p == CPU_BUF_FREE_HEX) {
			free_buf_count++;
		}
	}

	T_ASSERT_GE_ULONG(free_buf_count, 2, "At least 2 buffers should be free");
	cons_test_ops_count = 0;

	kr = kernel_thread_start(alloc_free_func, (void *)1000, &thread);
	T_ASSERT_EQ_INT(kr, KERN_SUCCESS, "kernel_thread_start returned successfully");

	/* yeild cpu to give other thread chance to get on-core */
	delay(100);

	alloc_free_func((void *)1000, 0);

	/* wait until other thread finishes its tasks */
	while (cons_test_ops_count < 2000) {
		delay(1000);
	}

	thread_deallocate(thread);
	/* verify again that atleast 2 slots are free */
	free_buf_count = 0;
	for (i = 0; i < MAX_CPU_SLOTS; i++) {
		p   = (uint32_t *)((uintptr_t)console_ring.buffer + console_ring.len + (i * sizeof(console_buf_t)));
		cbp = (console_buf_t *)(void *)p;
		/* p should either be allocated cpu buffer or have CPU_BUF_FREE_HEX in it */
		T_ASSERT(*p == CPU_BUF_FREE_HEX || cbp->buf_base == &cbp->buf[0], "");
		if (*p == CPU_BUF_FREE_HEX) {
			free_buf_count++;
		}
	}
	T_ASSERT_GE_ULONG(free_buf_count, 2, "At least 2 buffers should be free after alloc free tests");

	return KERN_SUCCESS;
}

kern_return_t
console_serial_test(void)
{
	unsigned long i;
	char buffer[CPU_BUFFER_LEN];
	uint32_t * p;
	console_buf_t * cbp;

	T_LOG("Checking console_ring status.");
	T_ASSERT_EQ_INT(console_ring.len, KERN_CONSOLE_RING_SIZE, "Console ring size is not correct.");
	T_ASSERT_GT_INT(KERN_CONSOLE_BUF_SIZE, KERN_CONSOLE_RING_SIZE, "kernel console buffer size is < allocation.");

	/* select the next slot from the per cpu buffers at end of console_ring.buffer */
	for (i = 0; i < MAX_CPU_SLOTS; i++) {
		p   = (uint32_t *)((uintptr_t)console_ring.buffer + console_ring.len + (i * sizeof(console_buf_t)));
		cbp = (console_buf_t *)(void *)p;
		/* p should either be allocated cpu buffer or have CPU_BUF_FREE_HEX in it */
		T_ASSERT(*p == CPU_BUF_FREE_HEX || cbp->buf_base == &cbp->buf[0], "verified initialization of cpu buffers p=%p", (void *)p);
	}

	/* setup buffer to be chars */
	for (i = 0; i < CPU_BUFFER_LEN; i++) {
		buffer[i] = (char)('0' + (i % 10));
	}
	buffer[CPU_BUFFER_LEN - 1] = '\0';

	T_LOG("Printing %d char string to serial one char at a time.", CPU_BUFFER_LEN);
	for (i = 0; i < CPU_BUFFER_LEN; i++) {
		printf("%c", buffer[i]);
	}
	printf("End\n");
	T_LOG("Printing %d char string to serial as a whole", CPU_BUFFER_LEN);
	printf("%s\n", buffer);

	T_LOG("Using console_write call repeatedly for 100 iterations");
	for (i = 0; i < 100; i++) {
		console_write(&buffer[0], 14);
		if ((i % 6) == 0) {
			printf("\n");
		}
	}
	printf("\n");

	T_LOG("Using T_LOG to print buffer %s", buffer);
	return KERN_SUCCESS;
}
#endif
