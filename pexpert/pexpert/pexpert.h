/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
#ifndef _PEXPERT_PEXPERT_H_
#define _PEXPERT_PEXPERT_H_

#include <sys/cdefs.h>

#include <IOKit/IOInterrupts.h>
#include <kern/kern_types.h>

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
	char *cause);

void PE_init_platform(
	boolean_t vm_initialized, 
	void *args);

void PE_init_kprintf(
	boolean_t vm_initialized);

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

void PE_install_interrupt_handler(
	void *nub, int source,
        void *target, IOInterruptHandler handler, void *refCon);

void kprintf(
	const char *fmt, ...);

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

struct PE_Video {
        unsigned long   v_baseAddr;     /* Base address of video memory */
        unsigned long   v_rowBytes;     /* Number of bytes per pixel row */
        unsigned long   v_width;        /* Width */
        unsigned long   v_height;       /* Height */
        unsigned long   v_depth;        /* Pixel Depth */
        unsigned long   v_display;      /* Text or Graphics */
	char		v_pixelFormat[64];
	long		v_resv[ 4 ];
};

typedef struct PE_Video       PE_Video;

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

extern void PE_display_icon( unsigned int flags,
			     const char * name );

typedef struct PE_state {
	boolean_t	initialized;
	PE_Video	video;
	void		*deviceTreeHead;
	void		*bootArgs;
#if __i386__
	void		*fakePPCBootArgs;
#endif
} PE_state_t;

extern PE_state_t PE_state;

extern char * PE_boot_args(
	void);

extern boolean_t PE_parse_boot_arg(
	char    *arg_string,
	void    *arg_ptr);

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

extern void PE_cpu_machine_init(
	cpu_id_t target,
	boolean_t boot);

extern void PE_cpu_machine_quiesce(
	cpu_id_t target);

extern void pe_init_debug(void);

__END_DECLS

#endif /* _PEXPERT_PEXPERT_H_ */
