/*
 * Copyright (c) 2000-2009 Apple Inc. All rights reserved.
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
#ifndef _PEXPERT_PEXPERT_H_
#define _PEXPERT_PEXPERT_H_

#include <sys/cdefs.h>

#ifdef KERNEL
#include <IOKit/IOInterrupts.h>
#include <kern/kern_types.h>
#endif

__BEGIN_DECLS
#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/machine/vm_types.h>

#ifdef PEXPERT_KERNEL_PRIVATE
#include <pexpert/protos.h>
#endif
#include <pexpert/boot.h>

#if	defined(PEXPERT_KERNEL_PRIVATE) || defined(IOKIT_KERNEL_PRIVATE)
typedef void *cpu_id_t;
#else
typedef void *cpu_id_t;
#endif


void PE_enter_debugger(
	const char *cause);

void PE_init_platform(
	boolean_t vm_initialized, 
	void *args);

/*
 * Copies the requested number of bytes from the "random-seed" property in
 * the device tree, and zeros the corresponding bytes in the device tree.
 * Returns the number of bytes actually copied.
 */
uint32_t PE_get_random_seed(
	unsigned char * dst_random_seed,
	uint32_t request_size);

uint32_t PE_i_can_has_debugger(
	uint32_t *);


#if KERNEL_PRIVATE

/*
 * Kexts should consult this bitmask to change behavior, since the kernel
 * may be configured as RELEASE but have MACH_ASSERT enabled, or boot args
 * may have changed the kernel behavior for statistics and kexts should
 * participate similarly
 */

#define kPEICanHasAssertions	0x00000001	/* Exceptional conditions should panic() instead of printf() */
#define kPEICanHasStatistics	0x00000002	/* Gather expensive statistics (that don't otherwise change behavior */
#define kPEICanHasDiagnosticAPI	0x00000004	/* Vend API to userspace or kexts that introspect kernel state */

extern uint32_t PE_i_can_has_kernel_configuration(void);

#endif /* KERNEL_PRIVATE */

void PE_init_kprintf(
	boolean_t vm_initialized);

extern int32_t gPESerialBaud;

extern uint8_t gPlatformECID[8];

extern uint32_t gPlatformMemoryID;

unsigned int PE_init_taproot(vm_offset_t *taddr);

extern void (*PE_kputc)(char c);

void PE_init_printf(
	boolean_t vm_initialized);

extern void (*PE_putc)(char c);

void PE_init_iokit(
	void);

struct clock_frequency_info_t {
  unsigned long bus_clock_rate_hz;
  unsigned long cpu_clock_rate_hz;
  unsigned long dec_clock_rate_hz;
  unsigned long bus_clock_rate_num;
  unsigned long bus_clock_rate_den;
  unsigned long bus_to_cpu_rate_num;
  unsigned long bus_to_cpu_rate_den;
  unsigned long bus_to_dec_rate_num;
  unsigned long bus_to_dec_rate_den;
  unsigned long timebase_frequency_hz;
  unsigned long timebase_frequency_num;
  unsigned long timebase_frequency_den;
  unsigned long long bus_frequency_hz;
  unsigned long long bus_frequency_min_hz;
  unsigned long long bus_frequency_max_hz;
  unsigned long long cpu_frequency_hz;
  unsigned long long cpu_frequency_min_hz;
  unsigned long long cpu_frequency_max_hz;
  unsigned long long prf_frequency_hz;
  unsigned long long prf_frequency_min_hz;
  unsigned long long prf_frequency_max_hz;
  unsigned long long mem_frequency_hz;
  unsigned long long mem_frequency_min_hz;
  unsigned long long mem_frequency_max_hz;
  unsigned long long fix_frequency_hz;
};

typedef struct clock_frequency_info_t clock_frequency_info_t;

extern clock_frequency_info_t gPEClockFrequencyInfo;

struct timebase_freq_t {
  unsigned long timebase_num;
  unsigned long timebase_den;
};

typedef void (*timebase_callback_func)(struct timebase_freq_t *timebase_freq);

void PE_register_timebase_callback(timebase_callback_func callback);

void PE_call_timebase_callback(void);

#ifdef KERNEL
void PE_install_interrupt_handler(
	void *nub, int source,
        void *target, IOInterruptHandler handler, void *refCon);
#endif

#ifndef _FN_KPRINTF
#define	_FN_KPRINTF
void kprintf(const char *fmt, ...) __printflike(1,2);
#endif

#if KERNEL_PRIVATE
void _consume_kprintf_args(int, ...);
#endif

#if CONFIG_NO_KPRINTF_STRINGS
#if KERNEL_PRIVATE
#define kprintf(x, ...) _consume_kprintf_args( 0, ## __VA_ARGS__ )
#else
#define kprintf(x, ...) do {} while (0)
#endif
#endif

void init_display_putc(unsigned char *baseaddr, int rowbytes, int height);
void display_putc(char c);

enum {
    kPEReadTOD,
    kPEWriteTOD
};
extern int (*PE_read_write_time_of_day)(
	unsigned int options, 
	long * secs);

enum {
    kPEWaitForInput 	= 0x00000001,
    kPERawInput		= 0x00000002
};
extern int (*PE_poll_input)(
	unsigned int options, 
	char * c);

extern int (*PE_write_IIC)(
	unsigned char addr, 
	unsigned char reg,
	unsigned char data);

/* Private Stuff - eventually put in pexpertprivate.h */
enum {
    kDebugTypeNone    = 0,
    kDebugTypeDisplay = 1,
    kDebugTypeSerial  = 2 
};

/*  Scale factor values for PE_Video.v_scale */
enum {
   kPEScaleFactorUnknown = 0,
   kPEScaleFactor1x      = 1,
   kPEScaleFactor2x      = 2
};

struct PE_Video {
        unsigned long   v_baseAddr;     /* Base address of video memory */
        unsigned long   v_rowBytes;     /* Number of bytes per pixel row */
        unsigned long   v_width;        /* Width */
        unsigned long   v_height;       /* Height */
        unsigned long   v_depth;        /* Pixel Depth */
        unsigned long   v_display;      /* Text or Graphics */
	char		v_pixelFormat[64];
	unsigned long	v_offset;	/* offset into video memory to start at */
	unsigned long	v_length;	/* length of video memory (0 for v_rowBytes * v_height) */
	unsigned char	v_rotate;	/* Rotation: 0:normal, 1:right 90, 2:left 180, 3:left 90 */
	unsigned char	v_scale;	/* Scale Factor for both X & Y */
	char		reserved1[2];
#ifdef __LP64__
	long		reserved2;
#else
	long		v_baseAddrHigh;
#endif
};

typedef struct PE_Video       PE_Video;

extern void initialize_screen(PE_Video *, unsigned int);

extern void dim_screen(void);

extern int PE_current_console(
	PE_Video *info);

extern void PE_create_console(
        void);

extern int PE_initialize_console(
	PE_Video *newInfo, 
	int op);

#define kPEGraphicsMode		1
#define kPETextMode		2
#define kPETextScreen		3
#define kPEAcquireScreen	4
#define kPEReleaseScreen	5
#define kPEEnableScreen	 	6
#define kPEDisableScreen	7
#define kPEBaseAddressChange	8
#define kPERefreshBootGraphics	9

extern void PE_display_icon( unsigned int flags,
			     const char * name );

typedef struct PE_state {
	boolean_t	initialized;
	PE_Video	video;
	void		*deviceTreeHead;
	void		*bootArgs;
} PE_state_t;

extern PE_state_t PE_state;

extern char * PE_boot_args(
	void);

#if !defined(__LP64__) && !defined(__arm__)
extern boolean_t PE_parse_boot_arg(
	const char	*arg_string,
	void    	*arg_ptr) __deprecated;
#endif

extern boolean_t PE_parse_boot_argn(
	const char	*arg_string,
	void    	*arg_ptr,
	int			max_arg);

#if XNU_KERNEL_PRIVATE
extern boolean_t PE_parse_boot_arg_str(
	const char *arg_string,
	char *      arg_ptr,
	int         size);
#endif /* XNU_KERNEL_PRIVATE */

extern boolean_t PE_get_default(
	const char	*property_name,
	void		*property_ptr,
	unsigned int max_property);

#define PE_default_value(_key, _variable, _default)	\
	do {															  \
		if (!PE_get_default((_key), &(_variable), sizeof(_variable))) \
			_variable = _default;									  \
	} while(0)

enum {
    kPEOptionKey	= 0x3a,
    kPECommandKey	= 0x37,
    kPEControlKey	= 0x36,
    kPEShiftKey		= 0x38
};

extern boolean_t PE_get_hotkey(
	unsigned char	key);

extern kern_return_t PE_cpu_start(
	cpu_id_t target,
	vm_offset_t start_paddr,
	vm_offset_t arg_paddr);

extern void PE_cpu_halt(
	cpu_id_t target);

extern void PE_cpu_signal(
	cpu_id_t source,
	cpu_id_t target);

extern void PE_cpu_signal_deferred(
	cpu_id_t source,
	cpu_id_t target);

extern void PE_cpu_signal_cancel(
	cpu_id_t source,
	cpu_id_t target);

extern void PE_cpu_machine_init(
	cpu_id_t target,
	boolean_t bootb);

extern void PE_cpu_machine_quiesce(
	cpu_id_t target);

extern void pe_init_debug(void);

extern boolean_t PE_imgsrc_mount_supported(void);


#if KERNEL_PRIVATE
boolean_t PE_reboot_on_panic(void);
void PE_sync_panic_buffers(void);
#endif

__END_DECLS

#endif /* _PEXPERT_PEXPERT_H_ */
