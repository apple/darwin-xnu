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
 * file: pe_init.c
 *    i386 platform expert initialization.
 */
#include <sys/types.h>
#include <mach/vm_param.h>
#include <pexpert/protos.h>
#include <pexpert/pexpert.h>
#include <pexpert/boot.h>
#include <pexpert/device_tree.h>
#include <pexpert/pe_images.h>
#include <kern/sched_prim.h>
#include <kern/debug.h>

#include "boot_images.h"

/* extern references */
extern void pe_identify_machine(void * args);

/* private globals */
PE_state_t  PE_state;

/* Clock Frequency Info */
clock_frequency_info_t gPEClockFrequencyInfo;

void *gPEEFISystemTable;
void *gPEEFIRuntimeServices;

int PE_initialize_console( PE_Video * info, int op )
{
    static int   last_console = -1;

    if (info) {
	info->v_offset  = 0;
	info->v_length  = 0;
	info->v_display = GRAPHICS_MODE;
    }

    switch ( op ) {

        case kPEDisableScreen:
            initialize_screen(info, op);
            kprintf("kPEDisableScreen %d\n", last_console);
	    if (!console_is_serial())
		last_console = switch_to_serial_console();
            break;

        case kPEEnableScreen:
            initialize_screen(info, op);
            kprintf("kPEEnableScreen %d\n", last_console);
            if( last_console != -1)
                switch_to_old_console( last_console);
            break;
	
        default:
            initialize_screen(info, op);
            break;
    }

    return 0;
}

void PE_init_iokit(void)
{
    enum { kMaxBootVar = 128 };
        
    typedef struct {
        char            name[32];
        unsigned long   length;
        unsigned long   value[2];
    } DriversPackageProp;

    boolean_t bootClutInitialized = FALSE;
    boolean_t norootInitialized = FALSE;
    DTEntry             entry;
    unsigned int	size;
    void **		map;
	boot_progress_element *bootPict;

    PE_init_kprintf(TRUE);
    PE_init_printf(TRUE);

    kprintf("Kernel boot args: '%s'\n", PE_boot_args());

    /*
     * Fetch the CLUT and the noroot image.
     */

    if( kSuccess == DTLookupEntry(NULL, "/chosen/memory-map", &entry)) {
	if( kSuccess == DTGetProperty(entry, "BootCLUT", (void **) &map, &size)) {
	    bcopy( map[0], appleClut8, sizeof(appleClut8) );
            bootClutInitialized = TRUE;
        }

	if( kSuccess == DTGetProperty(entry, "Pict-FailedBoot", (void **) &map, &size)) {
	    bootPict = (boot_progress_element *) map[0];
	    default_noroot.width  = bootPict->width;
	    default_noroot.height = bootPict->height;
	    default_noroot.dx     = 0;
	    default_noroot.dy     = bootPict->yOffset;
	    default_noroot_data   = &bootPict->data[0];
            norootInitialized = TRUE;
	}
    }

    if (!bootClutInitialized) {
    bcopy( (void *) (uintptr_t) bootClut, (void *) appleClut8, sizeof(appleClut8) );
    }

    if (!norootInitialized) {
    default_noroot.width  = kFailedBootWidth;
    default_noroot.height = kFailedBootHeight;
    default_noroot.dx     = 0;
    default_noroot.dy     = kFailedBootOffset;
    default_noroot_data   = failedBootPict;
    }
    
    /*
     * Initialize the panic UI
     */
    panic_ui_initialize( (unsigned char *) appleClut8 );

    /*
     * Initialize the spinning wheel (progress indicator).
     */
    vc_progress_initialize( &default_progress, default_progress_data,
                            (unsigned char *) appleClut8 );

    (void) StartIOKit( PE_state.deviceTreeHead, PE_state.bootArgs, gPEEFIRuntimeServices, NULL);
}

void PE_init_platform(boolean_t vm_initialized, void * _args)
{
    boot_args *args = (boot_args *)_args;

    if (PE_state.initialized == FALSE) {
	    PE_state.initialized        = TRUE;

        // New EFI-style
        PE_state.bootArgs           = _args;
        PE_state.deviceTreeHead	    = (void *) args->deviceTreeP;
        PE_state.video.v_baseAddr   = args->Video.v_baseAddr;
        PE_state.video.v_rowBytes   = args->Video.v_rowBytes;
        PE_state.video.v_width	    = args->Video.v_width;
        PE_state.video.v_height	    = args->Video.v_height;
        PE_state.video.v_depth	    = args->Video.v_depth;
        PE_state.video.v_display    = args->Video.v_display;
        strlcpy(PE_state.video.v_pixelFormat, "PPPPPPPP",
		sizeof(PE_state.video.v_pixelFormat));
    }

    if (!vm_initialized) {
		/* Hack! FIXME.. */ 
        outb(0x21, 0xff);   /* Maskout all interrupts Pic1 */
        outb(0xa1, 0xff);   /* Maskout all interrupts Pic2 */
 
        if (PE_state.deviceTreeHead) {
            DTInit(PE_state.deviceTreeHead);
    }

        pe_identify_machine(args);
    } else {
        pe_init_debug();
    }
}

void PE_create_console( void )
{
    if ( PE_state.video.v_display == GRAPHICS_MODE )
        PE_initialize_console( &PE_state.video, kPEGraphicsMode );
    else
        PE_initialize_console( &PE_state.video, kPETextMode );
}

int PE_current_console( PE_Video * info )
{
    *info = PE_state.video;

    return (0);
}

void PE_display_icon( __unused unsigned int flags, __unused const char * name )
{
    if ( default_noroot_data )
        vc_display_icon( &default_noroot, default_noroot_data );
}

boolean_t
PE_get_hotkey(__unused unsigned char key)
{
    return (FALSE);
}

static timebase_callback_func gTimebaseCallback;

void PE_register_timebase_callback(timebase_callback_func callback)
{
    gTimebaseCallback = callback;
  
    PE_call_timebase_callback();
}

void PE_call_timebase_callback(void)
{
  struct timebase_freq_t timebase_freq;
  unsigned long          num, den, cnt;
  
  num = gPEClockFrequencyInfo.bus_clock_rate_num * gPEClockFrequencyInfo.bus_to_dec_rate_num;
  den = gPEClockFrequencyInfo.bus_clock_rate_den * gPEClockFrequencyInfo.bus_to_dec_rate_den;
  
  cnt = 2;
  while (cnt <= den) {
    if ((num % cnt) || (den % cnt)) {
      cnt++;
      continue;
    }
    
    num /= cnt;
    den /= cnt;
  }
  
  timebase_freq.timebase_num = num;
  timebase_freq.timebase_den = den;
  
  if (gTimebaseCallback) gTimebaseCallback(&timebase_freq);
}

/*
 * The default (non-functional) PE_poll_input handler.
 */
static int
PE_stub_poll_input(__unused unsigned int options, char * c)
{
    *c = 0xff;
    return 1;  /* 0 for success, 1 for unsupported */
}

/*
 * Called by the kernel debugger to poll for keyboard input.
 * Keyboard drivers may replace the default stub function
 * with their polled-mode input function.
 */
int (*PE_poll_input)(unsigned int options, char * c)
	= PE_stub_poll_input;



