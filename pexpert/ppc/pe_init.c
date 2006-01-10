/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
 * file: pe_init.c
 *    PPC platform expert initialization.
 */
#include <mach/time_value.h>
#include <pexpert/protos.h>
#include <pexpert/pexpert.h>
#include <pexpert/ppc/interrupts.h>
#include <pexpert/device_tree.h>
#include <pexpert/pe_images.h>
#include <kern/debug.h>
#include <kern/sched_prim.h>


/* extern references */
void pe_identify_machine(void);

/* private globals */
PE_state_t PE_state;

/* Clock Frequency Info */
clock_frequency_info_t gPEClockFrequencyInfo;

static int PE_stub_read_write_time_of_day(unsigned int options, long * secs)
{
    // believe it or, BSD crashes if invalid time returned. FIXME.
    if( options == kPEReadTOD)
        *secs = 0xb2383c72;

    return 0;
}

static int PE_stub_poll_input(unsigned int options, char * c)
{
    *c = 0xff;

    return 1;
}

static int PE_stub_write_IIC(unsigned char addr, unsigned char reg,
				unsigned char data)
{
    return 1;
}

int (*PE_read_write_time_of_day)(unsigned int options, long * secs)
	= PE_stub_read_write_time_of_day;
int (*PE_poll_input)(unsigned int options, char * c)
	= PE_stub_poll_input;

int (*PE_write_IIC)(unsigned char addr, unsigned char reg,
				unsigned char data)
	= PE_stub_write_IIC;


int PE_initialize_console( PE_Video * info, int op )
{
    static int		last_console = -1;
    Boot_Video		bootInfo;
    Boot_Video	*	bInfo;

    if( info) {
        bootInfo.v_baseAddr		= info->v_baseAddr;
        bootInfo.v_rowBytes		= info->v_rowBytes;
        bootInfo.v_width		= info->v_width;
        bootInfo.v_height		= info->v_height;
        bootInfo.v_depth		= info->v_depth;
        bootInfo.v_display		= 0;
	bInfo = &bootInfo;
    } else
	bInfo = 0;

    switch( op ) {

	case kPEDisableScreen:
            initialize_screen((void *) bInfo, op);
            last_console = switch_to_serial_console();
            kprintf("kPEDisableScreen %d\n",last_console);
	    break;

	case kPEEnableScreen:
            initialize_screen((void *) bInfo, op);
            kprintf("kPEEnableScreen %d\n",last_console);
            if( last_console != -1)
                switch_to_old_console( last_console);
	    break;
	
	default:
            initialize_screen((void *) bInfo, op);
	    break;
    }

    return 0;
}

void PE_init_iokit(void)
{
    kern_return_t	ret;
    DTEntry		entry;
    int			size;
    void **		map;

    PE_init_kprintf(TRUE);
    PE_init_printf(TRUE);

    if( kSuccess == DTLookupEntry(0, "/chosen/memory-map", &entry)) {

	boot_progress_element * bootPict;

	if( kSuccess == DTGetProperty(entry, "BootCLUT", (void **) &map, &size))
	    bcopy( map[0], appleClut8, sizeof(appleClut8) );

	if( kSuccess == DTGetProperty(entry, "Pict-FailedBoot", (void **) &map, &size)) {

	    bootPict = (boot_progress_element *) map[0];
	    default_noroot.width  = bootPict->width;
	    default_noroot.height = bootPict->height;
	    default_noroot.dx     = 0;
	    default_noroot.dy     = bootPict->yOffset;
	    default_noroot_data   = &bootPict->data[0];
	}
    }
    panic_ui_initialize( (unsigned char *) appleClut8 );
    vc_progress_initialize( &default_progress, default_progress_data, (unsigned char *) appleClut8 );

    ret = StartIOKit( PE_state.deviceTreeHead, PE_state.bootArgs, (void *)0, (void *)0);
}

void PE_init_platform(boolean_t vm_initialized, void *_args)
{
	DTEntry dsouth, dnorth, root, dcpu;
	char *model;
	int msize, size;
	uint32_t *south, *north, *pdata, *ddata;
	int i;
	
	boot_args *args = (boot_args *)_args;

	if (PE_state.initialized == FALSE)
	{
	  PE_state.initialized		= TRUE;
	  PE_state.bootArgs		= _args;
	  PE_state.deviceTreeHead	= args->deviceTreeP;
	  PE_state.video.v_baseAddr	= args->Video.v_baseAddr;
	  PE_state.video.v_rowBytes	= args->Video.v_rowBytes;
	  PE_state.video.v_width	= args->Video.v_width;
	  PE_state.video.v_height	= args->Video.v_height;
	  PE_state.video.v_depth	= args->Video.v_depth;
	  PE_state.video.v_display	= args->Video.v_display;
	  strcpy( PE_state.video.v_pixelFormat, "PPPPPPPP");
	}

	if (!vm_initialized)
	{
            /*
             * Setup the OpenFirmware Device Tree routines
             * so the console can be found and the right I/O space
             * can be used..
             */
            DTInit(PE_state.deviceTreeHead);
	
            /* Setup gPEClockFrequencyInfo */
            pe_identify_machine();
	}
	else
	{
	    pe_init_debug();
	
	}
}

void PE_create_console( void )
{
    if ( PE_state.video.v_display )
        PE_initialize_console( &PE_state.video, kPEGraphicsMode );
    else
        PE_initialize_console( &PE_state.video, kPETextMode );
}

int PE_current_console( PE_Video * info )
{
    *info = PE_state.video;
    info->v_baseAddr = 0;
    return( 0);
}

void PE_display_icon(	unsigned int flags,
			const char * name )
{
    if( default_noroot_data)
	vc_display_icon( &default_noroot, default_noroot_data );
}

extern boolean_t PE_get_hotkey(
	unsigned char	key)
{
    unsigned char * adbKeymap;
    int		size;
    DTEntry	entry;

    if( (kSuccess != DTLookupEntry( 0, "/", &entry))
    ||  (kSuccess != DTGetProperty( entry, "AAPL,adb-keymap",
            (void **)&adbKeymap, &size))
    || (size != 16))

        return( FALSE);

    if( key > 127)
	return( FALSE);

    return( adbKeymap[ key / 8 ] & (0x80 >> (key & 7)));
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
  
  num = gPEClockFrequencyInfo.timebase_frequency_num;
  den = gPEClockFrequencyInfo.timebase_frequency_den;
  
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
