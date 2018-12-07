/*
 * Copyright (c) 2000-2017 Apple Inc. All rights reserved.
 *
 *    arm platform expert initialization.
 */
#include <sys/types.h>
#include <sys/kdebug.h>
#include <mach/vm_param.h>
#include <pexpert/protos.h>
#include <pexpert/pexpert.h>
#include <pexpert/boot.h>
#include <pexpert/device_tree.h>
#include <pexpert/pe_images.h>
#include <kern/sched_prim.h>
#include <machine/machine_routines.h>
#include <arm/caches_internal.h>
#include <kern/debug.h>
#include <libkern/section_keywords.h>

#if defined __arm__
#include <pexpert/arm/board_config.h>
#elif defined __arm64__
#include <pexpert/arm64/board_config.h>
#endif


/* extern references */
extern void     pe_identify_machine(boot_args *bootArgs);

/* static references */
static void	pe_prepare_images(void);

/* private globals */
SECURITY_READ_ONLY_LATE(PE_state_t) PE_state;
#define FW_VERS_LEN 128
char            firmware_version[FW_VERS_LEN];

/*
 * This variable is only modified once, when the BSP starts executing. We put it in __TEXT
 * as page protections on kernel text early in startup are read-write. The kernel is 
 * locked down later in start-up, said mappings become RO and thus this 
 * variable becomes immutable.
 *
 * See osfmk/arm/arm_vm_init.c for more information.
 */
SECURITY_READ_ONLY_SPECIAL_SECTION(volatile uint32_t, "__TEXT,__const")	debug_enabled = FALSE;

uint8_t         gPlatformECID[8];
uint32_t        gPlatformMemoryID;
static boolean_t vc_progress_initialized = FALSE;
uint64_t    last_hwaccess_thread = 0;
char     gTargetTypeBuffer[8];
char     gModelTypeBuffer[32];

/* Clock Frequency Info */
clock_frequency_info_t gPEClockFrequencyInfo;

vm_offset_t gPanicBase;
unsigned int gPanicSize;
struct embedded_panic_header *panic_info = NULL;

/* Maximum size of panic log excluding headers, in bytes */
static unsigned int panic_text_len;

/* Whether a console is standing by for panic logging */
static boolean_t panic_console_available = FALSE;

extern uint32_t crc32(uint32_t crc, const void *buf, size_t size);

void PE_slide_devicetree(vm_offset_t);

static void
check_for_panic_log(void)
{
#ifdef PLATFORM_PANIC_LOG_PADDR
	gPanicBase = ml_io_map_wcomb(PLATFORM_PANIC_LOG_PADDR, PLATFORM_PANIC_LOG_SIZE);
	panic_text_len = PLATFORM_PANIC_LOG_SIZE - sizeof(struct embedded_panic_header);
	gPanicSize = PLATFORM_PANIC_LOG_SIZE;
#else
	DTEntry entry, chosen;
	unsigned int size;
	uintptr_t *reg_prop;
	uint32_t *panic_region_length;

	/*
	 * Find the vram node in the device tree
	 */
	if (kSuccess != DTLookupEntry(0, "pram", &entry))
		return;

	if (kSuccess != DTGetProperty(entry, "reg", (void **)&reg_prop, &size))
		return;

	if (kSuccess != DTLookupEntry(0, "/chosen", &chosen))
		return;

	if (kSuccess != DTGetProperty(chosen, "embedded-panic-log-size", (void **) &panic_region_length, &size))
		return;

	/*
	 * Map the first page of VRAM into the kernel for use in case of
	 * panic
	 */
	/* Note: map as normal memory. */
	gPanicBase = ml_io_map_wcomb(reg_prop[0], panic_region_length[0]);

	/* Deduct the size of the panic header from the panic region size */
	panic_text_len = panic_region_length[0] - sizeof(struct embedded_panic_header);
	gPanicSize = panic_region_length[0];
#endif
	panic_info = (struct embedded_panic_header *)gPanicBase;

	/* Check if a shared memory console is running in the panic buffer */
	if (panic_info->eph_magic == 'SHMC') {
		panic_console_available = TRUE;
		return;
	}

	/* Check if there's a boot profile in the panic buffer */
	if (panic_info->eph_magic == 'BTRC') {
		return;
	}

	/*
	 * Check to see if a panic (FUNK) is in VRAM from the last time
	 */
	if (panic_info->eph_magic == EMBEDDED_PANIC_MAGIC) {
		printf("iBoot didn't extract panic log from previous session crash, this is bad\n");
	}

	/* Clear panic region */
	bzero((void *)gPanicBase, gPanicSize);
}

int
PE_initialize_console(PE_Video * info, int op)
{
	static int last_console = -1;

	if (info && (info != &PE_state.video)) info->v_scale = PE_state.video.v_scale;

	switch (op) {

	case kPEDisableScreen:
		initialize_screen(info, op);
		last_console = switch_to_serial_console();
		kprintf("kPEDisableScreen %d\n", last_console);
		break;

	case kPEEnableScreen:
		initialize_screen(info, op);
		if (info)
			PE_state.video = *info;
		kprintf("kPEEnableScreen %d\n", last_console);
		if (last_console != -1)
			switch_to_old_console(last_console);
		break;

	case kPEReleaseScreen:
		/*
		 * we don't show the progress indicator on boot, but want to
		 * show it afterwards.
		 */
		if (!vc_progress_initialized) {
			default_progress.dx = 0;
			default_progress.dy = 0;
			vc_progress_initialize(&default_progress,
					       default_progress_data1x, 
					       default_progress_data2x,
					       default_progress_data3x,
					       (unsigned char *) appleClut8);
			vc_progress_initialized = TRUE;
		}
		initialize_screen(info, op);
		break;

	default:
		initialize_screen(info, op);
		break;
	}

	return 0;
}

void
PE_init_iokit(void)
{
	DTEntry		entry;
	unsigned int	size, scale;
	unsigned long	display_size;
	void		**map;
	unsigned int	show_progress;
	int		*delta, image_size, flip;
	uint32_t	start_time_value = 0;
	uint32_t	debug_wait_start_value = 0;
	uint32_t	load_kernel_start_value = 0;
	uint32_t	populate_registry_time_value = 0;

	PE_init_kprintf(TRUE);
	PE_init_printf(TRUE);

	printf("iBoot version: %s\n", firmware_version);

	if (kSuccess == DTLookupEntry(0, "/chosen/memory-map", &entry)) {

		boot_progress_element *bootPict;

		if (kSuccess == DTGetProperty(entry, "BootCLUT", (void **) &map, &size))
			bcopy(map[0], appleClut8, sizeof(appleClut8));

		if (kSuccess == DTGetProperty(entry, "Pict-FailedBoot", (void **) &map, &size)) {

			bootPict = (boot_progress_element *) map[0];
			default_noroot.width = bootPict->width;
			default_noroot.height = bootPict->height;
			default_noroot.dx = 0;
			default_noroot.dy = bootPict->yOffset;
			default_noroot_data = &bootPict->data[0];
		}
	}

	pe_prepare_images();

	scale = PE_state.video.v_scale;
	flip = 1;

	if (PE_parse_boot_argn("-progress", &show_progress, sizeof (show_progress)) && show_progress) {
		/* Rotation: 0:normal, 1:right 90, 2:left 180, 3:left 90 */
		switch (PE_state.video.v_rotate) {
		case 2: 
			flip = -1;
			/* fall through */
		case 0:
			display_size = PE_state.video.v_height;
			image_size = default_progress.height;
			delta = &default_progress.dy;
			break;
		case 1:
			flip = -1;
			/* fall through */
		case 3:
		default:
			display_size = PE_state.video.v_width;
			image_size = default_progress.width;
			delta = &default_progress.dx;
		}
		assert(*delta >= 0);
		while (((unsigned)(*delta + image_size)) >= (display_size / 2)) {
			*delta -= 50 * scale;
			assert(*delta >= 0);
		}
		*delta *= flip;

		/* Check for DT-defined progress y delta */
		PE_get_default("progress-dy", &default_progress.dy, sizeof(default_progress.dy));

		vc_progress_initialize(&default_progress,
				       default_progress_data1x, 
				       default_progress_data2x,
				       default_progress_data3x,
				       (unsigned char *) appleClut8);
		vc_progress_initialized = TRUE;
	}

	if (kdebug_enable && kdebug_debugid_enabled(IOKDBG_CODE(DBG_BOOTER, 0))) {
		/* Trace iBoot-provided timing information. */
		if (kSuccess == DTLookupEntry(0, "/chosen/iBoot", &entry)) {
			uint32_t * value_ptr;

			if (kSuccess == DTGetProperty(entry, "start-time", (void **)&value_ptr, &size)) {
				if (size == sizeof(start_time_value))
					start_time_value = *value_ptr;
			}

			if (kSuccess == DTGetProperty(entry, "debug-wait-start", (void **)&value_ptr, &size)) {
				if (size == sizeof(debug_wait_start_value))
					debug_wait_start_value = *value_ptr;
			}

			if (kSuccess == DTGetProperty(entry, "load-kernel-start", (void **)&value_ptr, &size)) {
				if (size == sizeof(load_kernel_start_value))
					load_kernel_start_value = *value_ptr;
			}

			if (kSuccess == DTGetProperty(entry, "populate-registry-time", (void **)&value_ptr, &size)) {
				if (size == sizeof(populate_registry_time_value))
					populate_registry_time_value = *value_ptr;
			}
		}

		KDBG_RELEASE(IOKDBG_CODE(DBG_BOOTER, 0), start_time_value, debug_wait_start_value, load_kernel_start_value, populate_registry_time_value);
	}

	StartIOKit(PE_state.deviceTreeHead, PE_state.bootArgs, (void *) 0, (void *) 0);
}

void
PE_slide_devicetree(vm_offset_t slide)
{
	assert(PE_state.initialized);
	PE_state.deviceTreeHead += slide;
	DTInit(PE_state.deviceTreeHead);
}

void
PE_init_platform(boolean_t vm_initialized, void *args)
{
	DTEntry         entry;
	unsigned int	size;
	void          **prop;
	boot_args      *boot_args_ptr = (boot_args *) args;

	if (PE_state.initialized == FALSE) {
		PE_state.initialized = TRUE;
		PE_state.bootArgs = boot_args_ptr;
		PE_state.deviceTreeHead = boot_args_ptr->deviceTreeP;
		PE_state.video.v_baseAddr = boot_args_ptr->Video.v_baseAddr;
		PE_state.video.v_rowBytes = boot_args_ptr->Video.v_rowBytes;
		PE_state.video.v_width = boot_args_ptr->Video.v_width;
		PE_state.video.v_height = boot_args_ptr->Video.v_height;
		PE_state.video.v_depth = (boot_args_ptr->Video.v_depth >> kBootVideoDepthDepthShift) & kBootVideoDepthMask;
		PE_state.video.v_rotate = (boot_args_ptr->Video.v_depth >> kBootVideoDepthRotateShift) & kBootVideoDepthMask;
		PE_state.video.v_scale = ((boot_args_ptr->Video.v_depth >> kBootVideoDepthScaleShift) & kBootVideoDepthMask) + 1;
		PE_state.video.v_display = boot_args_ptr->Video.v_display;
		strlcpy(PE_state.video.v_pixelFormat, "BBBBBBBBGGGGGGGGRRRRRRRR", sizeof(PE_state.video.v_pixelFormat));
	}
	if (!vm_initialized) {
		/*
		 * Setup the Device Tree routines
		 * so the console can be found and the right I/O space
		 * can be used..
		 */
		DTInit(PE_state.deviceTreeHead);
		pe_identify_machine(boot_args_ptr);
	} else {
		pe_arm_init_interrupts(args);
		pe_arm_init_debug(args);
	}

	if (!vm_initialized) {
		if (kSuccess == (DTFindEntry("name", "device-tree", &entry))) {
			if (kSuccess == DTGetProperty(entry, "target-type",
				(void **)&prop, &size)) {
				if (size > sizeof(gTargetTypeBuffer))
					size = sizeof(gTargetTypeBuffer);
				bcopy(prop,gTargetTypeBuffer,size);
				gTargetTypeBuffer[size-1]='\0';
			}
		}
		if (kSuccess == (DTFindEntry("name", "device-tree", &entry))) {
			if (kSuccess == DTGetProperty(entry, "model",
				(void **)&prop, &size)) {
				if (size > sizeof(gModelTypeBuffer))
					size = sizeof(gModelTypeBuffer);
				bcopy(prop,gModelTypeBuffer,size);
				gModelTypeBuffer[size-1]='\0';
			}
		}
		if (kSuccess == DTLookupEntry(NULL, "/chosen", &entry)) {
			if (kSuccess == DTGetProperty(entry, "debug-enabled",
						      (void **) &prop, &size)) {
				/* 
				 * We purposefully modify a constified variable as
				 * it will get locked down by a trusted monitor or
				 * via page table mappings. We don't want people easily
				 * modifying this variable...
				 */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-qual"
				boolean_t *modify_debug_enabled = (boolean_t *) &debug_enabled;
				if (size > sizeof(uint32_t))
					size = sizeof(uint32_t);
				bcopy(prop, modify_debug_enabled, size);
#pragma clang diagnostic pop
			}
			if (kSuccess == DTGetProperty(entry, "firmware-version",
						      (void **) &prop, &size)) {
				if (size > sizeof(firmware_version))
					size = sizeof(firmware_version);
				bcopy(prop, firmware_version, size);
				firmware_version[size - 1] = '\0';
			}
			if (kSuccess == DTGetProperty(entry, "unique-chip-id",
						      (void **) &prop, &size)) {
				if (size > sizeof(gPlatformECID))
					size = sizeof(gPlatformECID);
				bcopy(prop,gPlatformECID,size);
			}
			if (kSuccess == DTGetProperty(entry, "dram-vendor-id",
						      (void **) &prop, &size)) {
				if (size > sizeof(gPlatformMemoryID))
					size = sizeof(gPlatformMemoryID);
				bcopy(prop,&gPlatformMemoryID,size);
			}
		}
		pe_init_debug();
	}
}

void
PE_create_console(void)
{
	/*
	 * Check the head of VRAM for a panic log saved on last panic.
	 * Do this before the VRAM is trashed.
	 */
	check_for_panic_log();

	if (PE_state.video.v_display)
		PE_initialize_console(&PE_state.video, kPEGraphicsMode);
	else
		PE_initialize_console(&PE_state.video, kPETextMode);
}

int
PE_current_console(PE_Video * info)
{
	*info = PE_state.video;
	return (0);
}

void
PE_display_icon(__unused unsigned int flags, __unused const char *name)
{
	if (default_noroot_data)
		vc_display_icon(&default_noroot, default_noroot_data);
}

extern          boolean_t
PE_get_hotkey(__unused unsigned char key)
{
	return (FALSE);
}

static timebase_callback_func gTimebaseCallback;

void
PE_register_timebase_callback(timebase_callback_func callback)
{
	gTimebaseCallback = callback;

	PE_call_timebase_callback();
}

void
PE_call_timebase_callback(void)
{
	struct timebase_freq_t timebase_freq;

	timebase_freq.timebase_num = gPEClockFrequencyInfo.timebase_frequency_hz;
	timebase_freq.timebase_den = 1;

	if (gTimebaseCallback)
		gTimebaseCallback(&timebase_freq);
}

/*
 * The default PE_poll_input handler.
 */
static int
PE_stub_poll_input(__unused unsigned int options, char *c)
{
	*c = uart_getc();
	return 0;		/* 0 for success, 1 for unsupported */
}

/*
 * Called by the kernel debugger to poll for keyboard input.
 * Keyboard drivers may replace the default stub function
 * with their polled-mode input function.
 */
int             (*PE_poll_input) (unsigned int options, char *c) = PE_stub_poll_input;

/*
 * This routine will return 1 if you are running on a device with a variant
 * of iBoot that allows debugging. This is typically not the case on production
 * fused parts (even when running development variants of iBoot).
 *
 * The routine takes an optional argument of the flags passed to debug="" so
 * kexts don't have to parse the boot arg themselves.
 */
uint32_t
PE_i_can_has_debugger(uint32_t *debug_flags)
{
	if (debug_flags) {
#if DEVELOPMENT || DEBUG
		assert(debug_boot_arg_inited);
#endif
		if (debug_enabled)
			*debug_flags = debug_boot_arg;	
		else
			*debug_flags = 0;
	}
	return (debug_enabled);
}

/*
 * This routine returns TRUE if the device is configured
 * with panic debugging enabled.
 */
boolean_t
PE_panic_debugging_enabled()
{
	return panicDebugging;
}

void
PE_save_buffer_to_vram(unsigned char *buf, unsigned int *size)
{
	if (!panic_info || !size) {
		return;
	}

	if (!buf) {
		*size = panic_text_len;
		return;
	}

	if (*size == 0) {
		return;
	}

	*size = *size > panic_text_len ? panic_text_len : *size;
	if (panic_info->eph_magic != EMBEDDED_PANIC_MAGIC)
		printf("Error!! Current Magic 0x%X, expected value 0x%x", panic_info->eph_magic, EMBEDDED_PANIC_MAGIC);

	/* CRC everything after the CRC itself - starting with the panic header version */
	panic_info->eph_crc = crc32(0L, &panic_info->eph_version, (panic_text_len +
				sizeof(struct embedded_panic_header) - offsetof(struct embedded_panic_header, eph_version)));
}

uint32_t
PE_get_offset_into_panic_region(char *location)
{
	assert(panic_info != NULL);
	assert(location > (char *) panic_info);
	assert((unsigned int)(location - (char *) panic_info) < panic_text_len);

	return (uint32_t) (location - gPanicBase);
}

void
PE_init_panicheader()
{
	if (!panic_info)
		return;

	bzero(panic_info, sizeof(struct embedded_panic_header));

	/*
	 * The panic log begins immediately after the panic header -- debugger synchronization and other functions
	 * may log into this region before we've become the exclusive panicking CPU and initialize the header here.
	 */
	panic_info->eph_panic_log_offset = PE_get_offset_into_panic_region(debug_buf_base);

	panic_info->eph_magic = EMBEDDED_PANIC_MAGIC;
	panic_info->eph_version = EMBEDDED_PANIC_HEADER_CURRENT_VERSION;

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
	if (!panic_info)
		return;

	/*
	 * If the panic log offset is not set, re-init the panic header
	 */
	if (panic_info->eph_panic_log_offset == 0) {
		PE_init_panicheader();
		panic_info->eph_panic_flags |= EMBEDDED_PANIC_HEADER_FLAG_NESTED_PANIC;
		return;
	}

	panic_info->eph_panic_flags |= EMBEDDED_PANIC_HEADER_FLAG_NESTED_PANIC;

	/*
	 * If the panic log length is not set, set the end to
	 * the current location of the debug_buf_ptr to close it.
	 */
	if (panic_info->eph_panic_log_len == 0) {
		panic_info->eph_panic_log_len = PE_get_offset_into_panic_region(debug_buf_ptr);

		/* If this assert fires, it's indicative of corruption in the panic region */
		assert(panic_info->eph_other_log_offset == panic_info->eph_other_log_len == 0);
	}

	/* If this assert fires, it's likely indicative of corruption in the panic region */
	assert(((panic_info->eph_stackshot_offset == 0) && (panic_info->eph_stackshot_len == 0)) ||
			((panic_info->eph_stackshot_offset != 0) && (panic_info->eph_stackshot_len != 0)));

	/*
	 * If we haven't set up the other log yet, set the beginning of the other log
	 * to the current location of the debug_buf_ptr
	 */
	if (panic_info->eph_other_log_offset == 0) {
		panic_info->eph_other_log_offset = PE_get_offset_into_panic_region(debug_buf_ptr);

		/* If this assert fires, it's indicative of corruption in the panic region */
		assert(panic_info->eph_other_log_len == 0);
	}

	return;
}

boolean_t
PE_reboot_on_panic(void)
{
	uint32_t debug_flags;

	if (PE_i_can_has_debugger(&debug_flags)
		&& (debug_flags & DB_NMI)) {
		/* kernel debugging is active */
		return FALSE;
	} else {
		return TRUE;
	}
}

void
PE_sync_panic_buffers(void)
{
	/*
	 * rdar://problem/26453070:
	 * The iBoot panic region is write-combined on arm64.  We must flush dirty lines
	 * from L1/L2 as late as possible before reset, with no further reads of the panic
	 * region between the flush and the reset.  Some targets have an additional memcache (L3),
	 * and a read may bring dirty lines out of L3 and back into L1/L2, causing the lines to
	 * be discarded on reset.  If we can make sure the lines are flushed to L3/DRAM,
	 * the platform reset handler will flush any L3.
	 */
	if (gPanicBase)
		CleanPoC_DcacheRegion_Force(gPanicBase, gPanicSize);
}

static void
pe_prepare_images(void)
{
	if ((1 & PE_state.video.v_rotate) != 0) {
		// Only square square images with radial symmetry are supported
		// No need to actually rotate the data

		// Swap the dx and dy offsets
		uint32_t tmp = default_progress.dx;
		default_progress.dx = default_progress.dy;
		default_progress.dy = tmp;
	}
#if 0
	uint32_t cnt, cnt2, cnt3, cnt4;
	uint32_t tmp, width, height;
	uint8_t  data, *new_data;
	const uint8_t *old_data;

	width  = default_progress.width;
	height = default_progress.height * default_progress.count;

	// Scale images if the UI is being scaled
	if (PE_state.video.v_scale > 1) {
		new_data = kalloc(width * height * scale * scale);
		if (new_data != 0) {
			old_data = default_progress_data;
			default_progress_data = new_data;
			for (cnt = 0; cnt < height; cnt++) {
				for (cnt2 = 0; cnt2 < width; cnt2++) {
					data = *(old_data++);
					for (cnt3 = 0; cnt3 < scale; cnt3++) {
						for (cnt4 = 0; cnt4 < scale; cnt4++) {
							new_data[width * scale * cnt3 + cnt4] = data;
						}
					}
					new_data += scale;
				}
				new_data += width * scale * (scale - 1);
			}
			default_progress.width  *= scale;
			default_progress.height *= scale;
			default_progress.dx     *= scale;
			default_progress.dy     *= scale;
		}
	}
#endif
}

void
PE_mark_hwaccess(uint64_t thread)
{
	last_hwaccess_thread = thread;
	asm volatile("dmb ish");
}
