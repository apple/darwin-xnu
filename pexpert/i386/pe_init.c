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
#include <machine/machine_routines.h>
#include <pexpert/protos.h>
#include <pexpert/pexpert.h>
#include <pexpert/boot.h>
#include <pexpert/device_tree.h>
#include <pexpert/pe_images.h>
#include <kern/sched_prim.h>
#include <kern/debug.h>

#if CONFIG_CSR
#include <sys/csr.h>
#endif

#include "boot_images.h"

/* extern references */
extern void pe_identify_machine(void * args);

/* private globals */
PE_state_t  PE_state;

/* Clock Frequency Info */
clock_frequency_info_t gPEClockFrequencyInfo;

void *gPEEFISystemTable;
void *gPEEFIRuntimeServices;

static boot_icon_element* norootIcon_lzss;
static const uint8_t*     norootClut_lzss;

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
            if (info) PE_state.video = *info;
            kprintf("kPEEnableScreen %d\n", last_console);
            if( last_console != -1)
                switch_to_old_console( last_console);
            break;
	
        case kPEBaseAddressChange:
            if (info) PE_state.video = *info;
            /* fall thru */

        default:
            initialize_screen(info, op);
            break;
    }

    return 0;
}

void PE_init_iokit(void)
{
    enum { kMaxBootVar = 128 };
        
    boolean_t bootClutInitialized = FALSE;
    boolean_t noroot_rle_Initialized = FALSE;

    DTEntry             entry;
    unsigned int	size;
    uint32_t		*map;
	boot_progress_element *bootPict;

    norootIcon_lzss = NULL;
    norootClut_lzss = NULL;

    PE_init_kprintf(TRUE);
    PE_init_printf(TRUE);

    kprintf("Kernel boot args: '%s'\n", PE_boot_args());

    /*
     * Fetch the CLUT and the noroot image.
     */

    if( kSuccess == DTLookupEntry(NULL, "/chosen/memory-map", &entry)) {
        if( kSuccess == DTGetProperty(entry, "BootCLUT", (void **) &map, &size)) {
            if (sizeof(appleClut8) <= map[1]) {
                bcopy( (void *)ml_static_ptovirt(map[0]), appleClut8, sizeof(appleClut8) );
                bootClutInitialized = TRUE;
            }
        }

        if( kSuccess == DTGetProperty(entry, "Pict-FailedBoot", (void **) &map, &size)) {
            bootPict = (boot_progress_element *) ml_static_ptovirt(map[0]);
            default_noroot.width  = bootPict->width;
            default_noroot.height = bootPict->height;
            default_noroot.dx     = 0;
            default_noroot.dy     = bootPict->yOffset;
            default_noroot_data   = &bootPict->data[0];
            noroot_rle_Initialized = TRUE;
        }

        if( kSuccess == DTGetProperty(entry, "FailedCLUT", (void **) &map, &size)) {
	        norootClut_lzss = (uint8_t*) ml_static_ptovirt(map[0]);
        }

        if( kSuccess == DTGetProperty(entry, "FailedImage", (void **) &map, &size)) {
            norootIcon_lzss = (boot_icon_element *) ml_static_ptovirt(map[0]);
            if (norootClut_lzss == NULL) {
                    printf("ERROR: No FailedCLUT provided for noroot icon!\n");
            }
        }
    }

    if (!bootClutInitialized) {
        bcopy( (void *) (uintptr_t) bootClut, (void *) appleClut8, sizeof(appleClut8) );
    }

    if (!noroot_rle_Initialized) {
        default_noroot.width  = kFailedBootWidth;
        default_noroot.height = kFailedBootHeight;
        default_noroot.dx     = 0;
        default_noroot.dy     = kFailedBootOffset;
        default_noroot_data   = failedBootPict;
    }
    
    /*
     * Initialize the spinning wheel (progress indicator).
     */
    vc_progress_initialize(&default_progress, 
			    default_progress_data1x,
			    default_progress_data2x, 
			    default_progress_data3x, 
			    (unsigned char *) appleClut8);

    StartIOKit( PE_state.deviceTreeHead, PE_state.bootArgs, gPEEFIRuntimeServices, NULL);
}

void PE_init_platform(boolean_t vm_initialized, void * _args)
{
    boot_args *args = (boot_args *)_args;

    if (PE_state.initialized == FALSE) {
	    PE_state.initialized        = TRUE;

        // New EFI-style
        PE_state.bootArgs           = _args;
        PE_state.deviceTreeHead	    = (void *) ml_static_ptovirt(args->deviceTreeP);
        if (args->Video.v_baseAddr) {
            PE_state.video.v_baseAddr   = args->Video.v_baseAddr; // remains physical address
            PE_state.video.v_rowBytes   = args->Video.v_rowBytes;
            PE_state.video.v_width	    = args->Video.v_width;
            PE_state.video.v_height	    = args->Video.v_height;
            PE_state.video.v_depth	    = args->Video.v_depth;
            PE_state.video.v_display    = args->Video.v_display;
            strlcpy(PE_state.video.v_pixelFormat, "PPPPPPPP",
                sizeof(PE_state.video.v_pixelFormat));
        } else {
            PE_state.video.v_baseAddr   = args->VideoV1.v_baseAddr; // remains physical address
            PE_state.video.v_rowBytes   = args->VideoV1.v_rowBytes;
            PE_state.video.v_width	    = args->VideoV1.v_width;
            PE_state.video.v_height	    = args->VideoV1.v_height;
            PE_state.video.v_depth	    = args->VideoV1.v_depth;
            PE_state.video.v_display    = args->VideoV1.v_display;
            strlcpy(PE_state.video.v_pixelFormat, "PPPPPPPP",
                    sizeof(PE_state.video.v_pixelFormat));
        }

#ifdef  kBootArgsFlagHiDPI
	if (args->flags & kBootArgsFlagHiDPI)
                PE_state.video.v_scale = kPEScaleFactor2x;
	else
                PE_state.video.v_scale = kPEScaleFactor1x;
#else
	PE_state.video.v_scale = kPEScaleFactor1x;
#endif
    }

    if (!vm_initialized) {

        if (PE_state.deviceTreeHead) {
            DTInit(PE_state.deviceTreeHead);
        }

        pe_identify_machine(args);
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
    if ( norootIcon_lzss && norootClut_lzss ) {
        uint32_t width  = norootIcon_lzss->width;
        uint32_t height = norootIcon_lzss->height;
        uint32_t x = ((PE_state.video.v_width  - width) / 2);
        uint32_t y = ((PE_state.video.v_height - height) / 2) + norootIcon_lzss->y_offset_from_center;

        vc_display_lzss_icon(x, y, width, height,
                             &norootIcon_lzss->data[0],
                             norootIcon_lzss->data_size,
                             norootClut_lzss);
    }
    else if ( default_noroot_data ) {
        vc_display_icon( &default_noroot, default_noroot_data );
    } else {
        printf("ERROR: No data found for noroot icon!\n");
    }
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

boolean_t
PE_reboot_on_panic(void)
{
	boot_args *args = (boot_args *)PE_state.bootArgs;

	if (args->flags & kBootArgsFlagRebootOnPanic)
		return TRUE;
	else
		return FALSE;
}

void
PE_sync_panic_buffers(void)
{
}

/* rdar://problem/21244753 */
uint32_t
PE_i_can_has_debugger(uint32_t *debug_flags)
{
#if CONFIG_CSR
	if (csr_check(CSR_ALLOW_KERNEL_DEBUGGER) != 0) {
		if (debug_flags)
			*debug_flags = 0;
		return FALSE;
	}
#endif
	if (debug_flags) {
		*debug_flags = debug_boot_arg;
	}
	return TRUE;
}

uint32_t
PE_get_offset_into_panic_region(char *location)
{
	assert(panic_info != NULL);
	assert(location > (char *) panic_info);

	return (uint32_t) (location - debug_buf);
}

void
PE_init_panicheader()
{
	bzero(panic_info, offsetof(struct macos_panic_header, mph_data));
	panic_info->mph_panic_log_offset = PE_get_offset_into_panic_region(debug_buf_base);

	panic_info->mph_magic = MACOS_PANIC_MAGIC;
	panic_info->mph_version = MACOS_PANIC_HEADER_CURRENT_VERSION;

	return;
}

/*
 * Tries to update the panic header to keep it consistent on nested panics.
 *
 * NOTE: The purpose of this function is NOT to detect/correct corruption in the panic region,
 *       it is to update the panic header to make it consistent when we nest panics.
 */
void
PE_update_panicheader_nestedpanic()
{
	/* If the panic log offset is not set, re-init the panic header */
	if (panic_info->mph_panic_log_offset == 0) {
		PE_init_panicheader();
		panic_info->mph_panic_flags |= MACOS_PANIC_HEADER_FLAG_NESTED_PANIC;
		return;
	}

	panic_info->mph_panic_flags |= MACOS_PANIC_HEADER_FLAG_NESTED_PANIC;

	/* macOS panic logs include nested panic data, so don't touch the panic log length here */

	return;
}
