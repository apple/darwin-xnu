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
#include <kern/debug.h>

#include "fakePPCStructs.h"
#include "fakePPCDeviceTree.h"

/* extern references */
extern void pe_identify_machine(void * args);
extern void initialize_screen(void *, unsigned int);

/* Local references */
static vm_offset_t mapframebuffer(caddr_t,int);
static vm_offset_t PE_fb_vaddr = 0;
static int         PE_fb_mode  = TEXT_MODE;
static KERNBOOTSTRUCT * PE_kbp = 0;

/* private globals */
PE_state_t  PE_state;
dt_data     gMemoryMapNode;
dt_data     gDriversProp;

/* Clock Frequency Info */
clock_frequency_info_t gPEClockFrequencyInfo;

int PE_initialize_console( PE_Video * info, int op )
{
    static int   last_console = -1;
    Boot_Video   bootInfo;
    Boot_Video * bInfo;

    /*
     * Refuse changes from outside pexpert.
     * The video mode setup by the booter cannot be changed.
     */
    if ( info && (info == &PE_state.video) )
    {
        bootInfo.v_baseAddr	 = PE_fb_vaddr;
        bootInfo.v_rowBytes	 = info->v_rowBytes;
        bootInfo.v_width     = info->v_width;
        bootInfo.v_height    = info->v_height;
        bootInfo.v_depth     = info->v_depth;
        bootInfo.v_display   = PE_fb_mode;
        bInfo = &bootInfo;
    }
    else
        bInfo = 0;

    switch ( op ) {

        case kPEDisableScreen:
            initialize_screen((void *) bInfo, op);
#ifdef FIXME
            last_console = switch_to_serial_console();
#endif
            kprintf("kPEDisableScreen %d\n", last_console);
            break;

        case kPEEnableScreen:
            initialize_screen((void *) bInfo, op);
            kprintf("kPEEnableScreen %d\n", last_console);
#ifdef FIXME
            if( last_console != -1)
                switch_to_old_console( last_console);
#endif
            break;
	
        default:
            initialize_screen((void *) bInfo, op);
            break;
    }

    return 0;
}

void PE_init_iokit(void)
{
    long *          dt;
    void *          desc;
    unsigned char * data;
    unsigned char * clut;

    typedef struct {
        char            name[32];
        unsigned long   length;
        unsigned long   value[2];
    } DriversPackageProp;

    /*
     * Update the fake device tree with the driver information provided by
     * the booter.
     */

	gDriversProp.length   = PE_kbp->numBootDrivers * sizeof(DriversPackageProp);
    gMemoryMapNode.length = 2 * sizeof(long);

    dt = (long *) createdt( fakePPCDeviceTree,
            	  &((boot_args*)PE_state.fakePPCBootArgs)->deviceTreeLength );

    if ( dt )
    {
        DriversPackageProp * prop = (DriversPackageProp *) gDriversProp.address;
        int i;

        /* Copy driver info in kernBootStruct to fake device tree */

        for ( i = 0; i < PE_kbp->numBootDrivers; i++, prop++ )
        {
            switch ( PE_kbp->driverConfig[i].type )
            {
                case kBootDriverTypeKEXT:
                    sprintf(prop->name, "Driver-%lx", PE_kbp->driverConfig[i].address);
                    break;
                
                 case kBootDriverTypeMKEXT:
                    sprintf(prop->name, "DriversPackage-%lx", PE_kbp->driverConfig[i].address);
                    break;

                default:
                    sprintf(prop->name, "DriverBogus-%lx", PE_kbp->driverConfig[i].address);
                    break;
            }
            prop->length   = sizeof(prop->value);
            prop->value[0] = PE_kbp->driverConfig[i].address;
            prop->value[1] = PE_kbp->driverConfig[i].size;
        }

        *gMemoryMapNode.address = PE_kbp->numBootDrivers + 1;
    }

    /* Setup powermac_info and powermac_machine_info structures */

    ((boot_args*)PE_state.fakePPCBootArgs)->deviceTreeP	= (unsigned long *) dt;
    ((boot_args*)PE_state.fakePPCBootArgs)->topOfKernelData	= (unsigned int) kalloc(0x2000);

    /* 
     * Setup the OpenFirmware Device Tree routines
     * so the console can be found and the right I/O space 
     * can be used..
     */
    DTInit(dt);

    /*
     * Initialize the spinning wheel (progress indicator).
     */
    clut = appleClut8;
    desc = &default_progress;
    data = default_progress_data;

    vc_progress_initialize( desc, data, clut );

    PE_initialize_console( (PE_Video *) 0, kPEAcquireScreen );

    (void) StartIOKit( (void*)dt, (void*)PE_state.fakePPCBootArgs, 0, 0);
}

void PE_init_platform(boolean_t vm_initialized, void * args)
{
	if (PE_state.initialized == FALSE)
	{
        extern unsigned int halt_in_debugger, disableDebugOuput;
        unsigned int        debug_arg;

        PE_kbp = (KERNBOOTSTRUCT *) args;

	    PE_state.initialized        = TRUE;
	    PE_state.bootArgs           = args;
	    PE_state.video.v_baseAddr   = PE_kbp->video.v_baseAddr;
	    PE_state.video.v_rowBytes   = PE_kbp->video.v_rowBytes;
	    PE_state.video.v_height     = PE_kbp->video.v_height;
	    PE_state.video.v_width      = PE_kbp->video.v_width;
	    PE_state.video.v_depth      = PE_kbp->video.v_depth;
        PE_state.video.v_display    = PE_kbp->video.v_display;
        PE_fb_mode                  = PE_kbp->graphicsMode;
	    PE_state.fakePPCBootArgs    = (boot_args *)&fakePPCBootArgs;
	    ((boot_args *)PE_state.fakePPCBootArgs)->machineType	= 386;

        if (PE_fb_mode == TEXT_MODE)
        {
            /* Force a text display if the booter did not setup a
             * VESA frame buffer.
             */
            PE_state.video.v_display = 0;
        }

        /*
         * If DB_HALT flag is set, then cause a breakpoint to the debugger
         * immediately after the kernel debugger has been initialized.
         *
         * If DB_PRT flag is set, then enable debugger printf.
         */
        disableDebugOuput = TRUE; /* FIXME: override osfmk/i386/AT386/model_dep.c */

        if (PE_parse_boot_arg("debug", &debug_arg)) {
            if (debug_arg & DB_HALT) halt_in_debugger = 1;
            if (debug_arg & DB_PRT)  disableDebugOuput = FALSE; 
        }
    }

	if (!vm_initialized)
	{
		/* Hack! FIXME.. */ 
        outb(0x21, 0xff);   /* Maskout all interrupts Pic1 */
        outb(0xa1, 0xff);   /* Maskout all interrupts Pic2 */
 
        pe_identify_machine(args);
	}
	else
	{
        pe_init_debug();

        PE_create_console();
	}
}

void PE_create_console( void )
{
    if ( (PE_fb_vaddr == 0) && (PE_state.video.v_baseAddr != 0) )
    {
        PE_fb_vaddr = mapframebuffer((caddr_t) PE_state.video.v_baseAddr,
                                     (PE_fb_mode == TEXT_MODE)  ?
                      /* text mode */	PE_state.video.v_rowBytes :
                      /* grfx mode */	PE_state.video.v_rowBytes *
                                        PE_state.video.v_height);
    }

	if (PE_state.video.v_display)
        PE_initialize_console( &PE_state.video, kPEGraphicsMode );
    else
        PE_initialize_console( &PE_state.video, kPETextMode );
}

int PE_current_console( PE_Video * info )
{
    *info = PE_state.video;

    if ( PE_fb_mode == TEXT_MODE )
    {
        /*
         * FIXME: Prevent the IOBootFrameBuffer from starting up
         * when we are in Text mode.
         */
        info->v_baseAddr = 0;
        
        /*
         * Scale the size of the text screen from characters
         * to pixels.
         */
        info->v_width  *= 8;   // CHARWIDTH
        info->v_height *= 16;  // CHARHEIGHT
    }

    return (0);
}

void PE_display_icon( unsigned int flags,
                      const char * name )
{
}

extern boolean_t PE_get_hotkey( unsigned char key )
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
 * map the framebuffer into kernel vm and return the (virtual)
 * address.
 */
static vm_offset_t
mapframebuffer( caddr_t physaddr,  /* start of framebuffer */
                int     length)    /* num bytes to map */
{
    vm_offset_t vmaddr;

	if (physaddr != (caddr_t)trunc_page(physaddr))
        panic("Framebuffer not on page boundary");

	vmaddr = io_map((vm_offset_t)physaddr, length);
	if (vmaddr == 0)
        panic("can't alloc VM for framebuffer");

    return vmaddr;
}

/*
 * The default (non-functional) PE_poll_input handler.
 */
static int
PE_stub_poll_input(unsigned int options, char * c)
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
