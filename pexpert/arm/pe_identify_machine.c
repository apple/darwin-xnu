/*
 * Copyright (c) 2007-2017 Apple Inc. All rights reserved.
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
 */
#include <pexpert/pexpert.h>
#include <pexpert/boot.h>
#include <pexpert/protos.h>
#include <pexpert/device_tree.h>

#if defined(__arm__)
#include <pexpert/arm/board_config.h>
#elif defined(__arm64__)
#include <pexpert/arm64/board_config.h>
#endif

#include <machine/machine_routines.h>
#if DEVELOPMENT || DEBUG
#include <kern/simple_lock.h>
#include <kern/cpu_number.h>
#endif
/* Local declarations */
void            pe_identify_machine(boot_args * bootArgs);

/* External declarations */
extern void clean_mmu_dcache(void);

static char    *gPESoCDeviceType;
static char     gPESoCDeviceTypeBuffer[SOC_DEVICE_TYPE_BUFFER_SIZE];
static vm_offset_t gPESoCBasePhys;

static uint32_t gTCFG0Value;

static uint32_t pe_arm_init_timer(void *args);

#if DEVELOPMENT || DEBUG
decl_simple_lock_data(, panic_trace_lock; )
#endif
/*
 * pe_identify_machine:
 *
 * Sets up platform parameters. Returns:    nothing
 */
void
pe_identify_machine(boot_args * bootArgs)
{
	OpaqueDTEntryIterator iter;
	DTEntry         cpus, cpu;
	uint32_t        mclk = 0, hclk = 0, pclk = 0, tclk = 0, use_dt = 0;
	unsigned long  *value;
	unsigned int    size;
	int             err;

	(void)bootArgs;

	if (pe_arm_get_soc_base_phys() == 0) {
		return;
	}

	/* Clear the gPEClockFrequencyInfo struct */
	bzero((void *)&gPEClockFrequencyInfo, sizeof(clock_frequency_info_t));

	if (!strcmp(gPESoCDeviceType, "s3c2410-io")) {
		mclk = 192 << 23;
		hclk = mclk / 2;
		pclk = hclk / 2;
		tclk = (1 << (23 + 2)) / 10;
		tclk = pclk / tclk;

		gTCFG0Value = tclk - 1;

		tclk = pclk / (4 * tclk);       /* Calculate the "actual"
		                                 * Timer0 frequency in fixed
		                                 * point. */

		mclk = (mclk >> 17) * (125 * 125);
		hclk = (hclk >> 17) * (125 * 125);
		pclk = (pclk >> 17) * (125 * 125);
		tclk = (((((tclk * 125) + 2) >> 2) * 125) + (1 << 14)) >> 15;
	} else if (!strcmp(gPESoCDeviceType, "integratorcp-io")) {
		mclk = 200000000;
		hclk = mclk / 2;
		pclk = hclk / 2;
		tclk = 100000;
	} else if (!strcmp(gPESoCDeviceType, "olocreek-io")) {
		mclk = 1000000000;
		hclk = mclk / 8;
		pclk = hclk / 2;
		tclk = pclk;
	} else if (!strcmp(gPESoCDeviceType, "omap3430sdp-io")) {
		mclk = 332000000;
		hclk =  19200000;
		pclk = hclk;
		tclk = pclk;
	} else if (!strcmp(gPESoCDeviceType, "s5i3000-io")) {
		mclk = 400000000;
		hclk = mclk / 4;
		pclk = hclk / 2;
		tclk = 100000;  /* timer is at 100khz */
	} else if (!strcmp(gPESoCDeviceType, "bcm2837-io")) {
		mclk = 1200000000;
		hclk = mclk / 4;
		pclk = hclk / 2;
		tclk = 1000000;
	} else {
		use_dt = 1;
	}

	if (use_dt) {
		/* Start with default values. */
		gPEClockFrequencyInfo.timebase_frequency_hz = 24000000;
		gPEClockFrequencyInfo.bus_clock_rate_hz = 100000000;
		gPEClockFrequencyInfo.cpu_clock_rate_hz = 400000000;

		err = DTLookupEntry(NULL, "/cpus", &cpus);
		assert(err == kSuccess);

		err = DTInitEntryIterator(cpus, &iter);
		assert(err == kSuccess);

		while (kSuccess == DTIterateEntries(&iter, &cpu)) {
			if ((kSuccess != DTGetProperty(cpu, "state", (void **)&value, &size)) ||
			    (strncmp((char*)value, "running", size) != 0)) {
				continue;
			}

			/* Find the time base frequency first. */
			if (DTGetProperty(cpu, "timebase-frequency", (void **)&value, &size) == kSuccess) {
				/*
				 * timebase_frequency_hz is only 32 bits, and
				 * the device tree should never provide 64
				 * bits so this if should never be taken.
				 */
				if (size == 8) {
					gPEClockFrequencyInfo.timebase_frequency_hz = *(unsigned long long *)value;
				} else {
					gPEClockFrequencyInfo.timebase_frequency_hz = *value;
				}
			}
			gPEClockFrequencyInfo.dec_clock_rate_hz = gPEClockFrequencyInfo.timebase_frequency_hz;

			/* Find the bus frequency next. */
			if (DTGetProperty(cpu, "bus-frequency", (void **)&value, &size) == kSuccess) {
				if (size == 8) {
					gPEClockFrequencyInfo.bus_frequency_hz = *(unsigned long long *)value;
				} else {
					gPEClockFrequencyInfo.bus_frequency_hz = *value;
				}
			}
			gPEClockFrequencyInfo.bus_frequency_min_hz = gPEClockFrequencyInfo.bus_frequency_hz;
			gPEClockFrequencyInfo.bus_frequency_max_hz = gPEClockFrequencyInfo.bus_frequency_hz;

			if (gPEClockFrequencyInfo.bus_frequency_hz < 0x100000000ULL) {
				gPEClockFrequencyInfo.bus_clock_rate_hz = gPEClockFrequencyInfo.bus_frequency_hz;
			} else {
				gPEClockFrequencyInfo.bus_clock_rate_hz = 0xFFFFFFFF;
			}

			/* Find the memory frequency next. */
			if (DTGetProperty(cpu, "memory-frequency", (void **)&value, &size) == kSuccess) {
				if (size == 8) {
					gPEClockFrequencyInfo.mem_frequency_hz = *(unsigned long long *)value;
				} else {
					gPEClockFrequencyInfo.mem_frequency_hz = *value;
				}
			}
			gPEClockFrequencyInfo.mem_frequency_min_hz = gPEClockFrequencyInfo.mem_frequency_hz;
			gPEClockFrequencyInfo.mem_frequency_max_hz = gPEClockFrequencyInfo.mem_frequency_hz;

			/* Find the peripheral frequency next. */
			if (DTGetProperty(cpu, "peripheral-frequency", (void **)&value, &size) == kSuccess) {
				if (size == 8) {
					gPEClockFrequencyInfo.prf_frequency_hz = *(unsigned long long *)value;
				} else {
					gPEClockFrequencyInfo.prf_frequency_hz = *value;
				}
			}
			gPEClockFrequencyInfo.prf_frequency_min_hz = gPEClockFrequencyInfo.prf_frequency_hz;
			gPEClockFrequencyInfo.prf_frequency_max_hz = gPEClockFrequencyInfo.prf_frequency_hz;

			/* Find the fixed frequency next. */
			if (DTGetProperty(cpu, "fixed-frequency", (void **)&value, &size) == kSuccess) {
				if (size == 8) {
					gPEClockFrequencyInfo.fix_frequency_hz = *(unsigned long long *)value;
				} else {
					gPEClockFrequencyInfo.fix_frequency_hz = *value;
				}
			}
			/* Find the cpu frequency last. */
			if (DTGetProperty(cpu, "clock-frequency", (void **)&value, &size) == kSuccess) {
				if (size == 8) {
					gPEClockFrequencyInfo.cpu_frequency_hz = *(unsigned long long *)value;
				} else {
					gPEClockFrequencyInfo.cpu_frequency_hz = *value;
				}
			}
			gPEClockFrequencyInfo.cpu_frequency_min_hz = gPEClockFrequencyInfo.cpu_frequency_hz;
			gPEClockFrequencyInfo.cpu_frequency_max_hz = gPEClockFrequencyInfo.cpu_frequency_hz;

			if (gPEClockFrequencyInfo.cpu_frequency_hz < 0x100000000ULL) {
				gPEClockFrequencyInfo.cpu_clock_rate_hz = gPEClockFrequencyInfo.cpu_frequency_hz;
			} else {
				gPEClockFrequencyInfo.cpu_clock_rate_hz = 0xFFFFFFFF;
			}
		}
	} else {
		/* Use the canned values. */
		gPEClockFrequencyInfo.timebase_frequency_hz = tclk;
		gPEClockFrequencyInfo.fix_frequency_hz = tclk;
		gPEClockFrequencyInfo.bus_frequency_hz = hclk;
		gPEClockFrequencyInfo.cpu_frequency_hz = mclk;
		gPEClockFrequencyInfo.prf_frequency_hz = pclk;

		gPEClockFrequencyInfo.bus_frequency_min_hz = gPEClockFrequencyInfo.bus_frequency_hz;
		gPEClockFrequencyInfo.bus_frequency_max_hz = gPEClockFrequencyInfo.bus_frequency_hz;
		gPEClockFrequencyInfo.cpu_frequency_min_hz = gPEClockFrequencyInfo.cpu_frequency_hz;
		gPEClockFrequencyInfo.cpu_frequency_max_hz = gPEClockFrequencyInfo.cpu_frequency_hz;
		gPEClockFrequencyInfo.prf_frequency_min_hz = gPEClockFrequencyInfo.prf_frequency_hz;
		gPEClockFrequencyInfo.prf_frequency_max_hz = gPEClockFrequencyInfo.prf_frequency_hz;

		gPEClockFrequencyInfo.dec_clock_rate_hz = gPEClockFrequencyInfo.timebase_frequency_hz;
		gPEClockFrequencyInfo.bus_clock_rate_hz = gPEClockFrequencyInfo.bus_frequency_hz;
		gPEClockFrequencyInfo.cpu_clock_rate_hz = gPEClockFrequencyInfo.cpu_frequency_hz;
	}

	/* Set the num / den pairs form the hz values. */
	gPEClockFrequencyInfo.bus_clock_rate_num = gPEClockFrequencyInfo.bus_clock_rate_hz;
	gPEClockFrequencyInfo.bus_clock_rate_den = 1;

	gPEClockFrequencyInfo.bus_to_cpu_rate_num =
	    (2 * gPEClockFrequencyInfo.cpu_clock_rate_hz) / gPEClockFrequencyInfo.bus_clock_rate_hz;
	gPEClockFrequencyInfo.bus_to_cpu_rate_den = 2;

	gPEClockFrequencyInfo.bus_to_dec_rate_num = 1;
	gPEClockFrequencyInfo.bus_to_dec_rate_den =
	    gPEClockFrequencyInfo.bus_clock_rate_hz / gPEClockFrequencyInfo.dec_clock_rate_hz;
}

vm_offset_t
pe_arm_get_soc_base_phys(void)
{
	DTEntry         entryP;
	uintptr_t       *ranges_prop;
	uint32_t        prop_size;
	char           *tmpStr;

	if (DTFindEntry("name", "arm-io", &entryP) == kSuccess) {
		if (gPESoCDeviceType == 0) {
			DTGetProperty(entryP, "device_type", (void **)&tmpStr, &prop_size);
			strlcpy(gPESoCDeviceTypeBuffer, tmpStr, SOC_DEVICE_TYPE_BUFFER_SIZE);
			gPESoCDeviceType = gPESoCDeviceTypeBuffer;

			DTGetProperty(entryP, "ranges", (void **)&ranges_prop, &prop_size);
			gPESoCBasePhys = *(ranges_prop + 1);
		}
		return gPESoCBasePhys;
	}
	return 0;
}

uint32_t
pe_arm_get_soc_revision(void)
{
	DTEntry         entryP;
	uint32_t        *value;
	uint32_t        size;

	if ((DTFindEntry("name", "arm-io", &entryP) == kSuccess)
	    && (DTGetProperty(entryP, "chip-revision", (void **)&value, &size) == kSuccess)) {
		if (size == 8) {
			return (uint32_t)*(unsigned long long *)value;
		} else {
			return *value;
		}
	}
	return 0;
}


extern void     fleh_fiq_generic(void);

#if defined(ARM_BOARD_CLASS_S5L8960X)
static struct tbd_ops    s5l8960x_funcs = {NULL, NULL, NULL};
#endif /* defined(ARM_BOARD_CLASS_S5L8960X) */

#if defined(ARM_BOARD_CLASS_T7000)
static struct tbd_ops    t7000_funcs = {NULL, NULL, NULL};
#endif /* defined(ARM_BOARD_CLASS_T7000) */

#if defined(ARM_BOARD_CLASS_S7002)
extern void     fleh_fiq_s7002(void);
extern uint32_t s7002_get_decrementer(void);
extern void     s7002_set_decrementer(uint32_t);
static struct tbd_ops    s7002_funcs = {&fleh_fiq_s7002, &s7002_get_decrementer, &s7002_set_decrementer};
#endif /* defined(ARM_BOARD_CLASS_S7002) */

#if defined(ARM_BOARD_CLASS_S8000)
static struct tbd_ops    s8000_funcs = {NULL, NULL, NULL};
#endif /* defined(ARM_BOARD_CLASS_T7000) */

#if defined(ARM_BOARD_CLASS_T8002)
extern void     fleh_fiq_t8002(void);
extern uint32_t t8002_get_decrementer(void);
extern void     t8002_set_decrementer(uint32_t);
static struct tbd_ops    t8002_funcs = {&fleh_fiq_t8002, &t8002_get_decrementer, &t8002_set_decrementer};
#endif /* defined(ARM_BOARD_CLASS_T8002) */

#if defined(ARM_BOARD_CLASS_T8010)
static struct tbd_ops    t8010_funcs = {NULL, NULL, NULL};
#endif /* defined(ARM_BOARD_CLASS_T8010) */

#if defined(ARM_BOARD_CLASS_T8011)
static struct tbd_ops    t8011_funcs = {NULL, NULL, NULL};
#endif /* defined(ARM_BOARD_CLASS_T8011) */

#if defined(ARM_BOARD_CLASS_T8015)
static struct tbd_ops    t8015_funcs = {NULL, NULL, NULL};
#endif /* defined(ARM_BOARD_CLASS_T8015) */






#if defined(ARM_BOARD_CLASS_BCM2837)
static struct tbd_ops    bcm2837_funcs = {NULL, NULL, NULL};
#endif /* defined(ARM_BOARD_CLASS_BCM2837) */

vm_offset_t     gPicBase;
vm_offset_t     gTimerBase;
vm_offset_t     gSocPhys;

#if DEVELOPMENT || DEBUG
// This block contains the panic trace implementation

// These variables are local to this file, and contain the panic trace configuration information
typedef enum{
	panic_trace_disabled = 0,
	panic_trace_unused,
	panic_trace_enabled,
	panic_trace_alt_enabled,
} panic_trace_t;
static panic_trace_t bootarg_panic_trace;

// The command buffer contains the converted commands from the device tree for commanding cpu_halt, enable_trace, etc.
#define DEBUG_COMMAND_BUFFER_SIZE 256
typedef struct command_buffer_element {
	uintptr_t address;
	uint16_t destination_cpu_selector;
	uintptr_t value;
} command_buffer_element_t;
static command_buffer_element_t debug_command_buffer[DEBUG_COMMAND_BUFFER_SIZE];                // statically allocate to prevent needing alloc at runtime
static uint32_t  next_command_bufffer_entry = 0;                                                                                // index of next unused slot in debug_command_buffer

#define CPU_SELECTOR_SHIFT                              ((sizeof(int)-2)*8)
#define CPU_SELECTOR_MASK                               (0xFFFF << CPU_SELECTOR_SHIFT)
#define REGISTER_OFFSET_MASK                    (~CPU_SELECTOR_MASK)
#define REGISTER_OFFSET(register_prop)  (register_prop & REGISTER_OFFSET_MASK)
#define CPU_SELECTOR(register_offset)   (register_offset >> CPU_SELECTOR_SHIFT) // Upper 16bits holds the cpu selector
#define MAX_WINDOW_SIZE                                 0xFFFF
#define PE_ISSPACE(c)                                   (c == ' ' || c == '\t' || c == '\n' || c == '\12')
/*
 *  0x0000 - all cpus
 *  0x0001 - cpu 0
 *  0x0002 - cpu 1
 *  0x0004 - cpu 2
 *  0x0003 - cpu 0 and 1
 *  since it's 16bits, we can have up to 16 cpus
 */
#define ALL_CPUS 0x0000
#define IS_CPU_SELECTED(cpu_number, cpu_selector) (cpu_selector == ALL_CPUS ||  (cpu_selector & (1<<cpu_number) ) != 0 )

#define RESET_VIRTUAL_ADDRESS_WINDOW    0xFFFFFFFF

// Pointers into debug_command_buffer for each operation. Assumes runtime will init them to zero.
static command_buffer_element_t *cpu_halt;
static command_buffer_element_t *enable_trace;
static command_buffer_element_t *enable_alt_trace;
static command_buffer_element_t *trace_halt;

// Record which CPU is currently running one of our debug commands, so we can trap panic reentrancy to PE_arm_debug_panic_hook.
static int running_debug_command_on_cpu_number = -1;

static void
pe_init_debug_command(DTEntry entryP, command_buffer_element_t **command_buffer, const char* entry_name)
{
	uintptr_t       *reg_prop;
	uint32_t        prop_size, reg_window_size = 0, command_starting_index;
	uintptr_t       debug_reg_window = 0;

	if (command_buffer == 0) {
		return;
	}

	if (DTGetProperty(entryP, entry_name, (void **)&reg_prop, &prop_size) != kSuccess) {
		panic("pe_init_debug_command: failed to read property %s\n", entry_name);
	}

	// make sure command will fit
	if (next_command_bufffer_entry + prop_size / sizeof(uintptr_t) > DEBUG_COMMAND_BUFFER_SIZE - 1) {
		panic("pe_init_debug_command: property %s is %u bytes, command buffer only has %lu bytes remaining\n",
		    entry_name, prop_size, ((DEBUG_COMMAND_BUFFER_SIZE - 1) - next_command_bufffer_entry) * sizeof(uintptr_t));
	}

	// Hold the pointer in a temp variable and later assign it to command buffer, in case we panic while half-initialized
	command_starting_index = next_command_bufffer_entry;

	// convert to real virt addresses and stuff commands into debug_command_buffer
	for (; prop_size; reg_prop += 2, prop_size -= 2 * sizeof(uintptr_t)) {
		if (*reg_prop == RESET_VIRTUAL_ADDRESS_WINDOW) {
			debug_reg_window = 0; // Create a new window
		} else if (debug_reg_window == 0) {
			// create a window from virtual address to the specified physical address
			reg_window_size = ((uint32_t)*(reg_prop + 1));
			if (reg_window_size > MAX_WINDOW_SIZE) {
				panic("pe_init_debug_command: Command page size is %0x, exceeds the Maximum allowed page size 0f 0%x\n", reg_window_size, MAX_WINDOW_SIZE );
			}
			debug_reg_window =  ml_io_map(gSocPhys + *reg_prop, reg_window_size);
			// for debug -- kprintf("pe_init_debug_command: %s registers @ 0x%08lX for 0x%08lX\n", entry_name, debug_reg_window, *(reg_prop + 1) );
		} else {
			if ((REGISTER_OFFSET(*reg_prop) + sizeof(uintptr_t)) >= reg_window_size) {
				panic("pe_init_debug_command: Command Offset is %lx, exceeds allocated size of %x\n", REGISTER_OFFSET(*reg_prop), reg_window_size );
			}
			debug_command_buffer[next_command_bufffer_entry].address = debug_reg_window + REGISTER_OFFSET(*reg_prop);
			debug_command_buffer[next_command_bufffer_entry].destination_cpu_selector = CPU_SELECTOR(*reg_prop);
			debug_command_buffer[next_command_bufffer_entry++].value = *(reg_prop + 1);
		}
	}

	// null terminate the address field of the command to end it
	debug_command_buffer[next_command_bufffer_entry++].address = 0;

	// save pointer into table for this command
	*command_buffer = &debug_command_buffer[command_starting_index];
}

static void
pe_run_debug_command(command_buffer_element_t *command_buffer)
{
	// When both the CPUs panic, one will get stuck on the lock and the other CPU will be halted when the first executes the debug command
	simple_lock(&panic_trace_lock, LCK_GRP_NULL);
	running_debug_command_on_cpu_number = cpu_number();

	while (command_buffer && command_buffer->address) {
		if (IS_CPU_SELECTED(running_debug_command_on_cpu_number, command_buffer->destination_cpu_selector)) {
			*((volatile uintptr_t*)(command_buffer->address)) = command_buffer->value;      // register = value;
		}
		command_buffer++;
	}

	running_debug_command_on_cpu_number = -1;
	simple_unlock(&panic_trace_lock);
}


void
PE_arm_debug_enable_trace(void)
{
	switch (bootarg_panic_trace) {
	case panic_trace_enabled:
		pe_run_debug_command(enable_trace);
		break;

	case panic_trace_alt_enabled:
		pe_run_debug_command(enable_alt_trace);
		break;

	default:
		break;
	}
}

static void
PEARMDebugPanicHook(const char *str)
{
	(void)str; // not used

	// if panic trace is enabled
	if (bootarg_panic_trace != 0) {
		if (running_debug_command_on_cpu_number == cpu_number()) {
			// This is going to end badly if we don't trap, since we'd be panic-ing during our own code
			kprintf("## Panic Trace code caused the panic ##\n");
			return;  // allow the normal panic operation to occur.
		}

		// Stop tracing to freze the buffer and return to normal panic processing.
		pe_run_debug_command(trace_halt);
	}
}

void (*PE_arm_debug_panic_hook)(const char *str) = PEARMDebugPanicHook;

#else

void (*PE_arm_debug_panic_hook)(const char *str) = NULL;

#endif  // DEVELOPMENT || DEBUG

void
pe_arm_init_debug(void *args)
{
	DTEntry         entryP;
	uintptr_t       *reg_prop;
	uint32_t        prop_size;

	if (gSocPhys == 0) {
		kprintf("pe_arm_init_debug: failed to initialize gSocPhys == 0\n");
		return;
	}

	if (DTFindEntry("device_type", "cpu-debug-interface", &entryP) == kSuccess) {
		if (args != NULL) {
			if (DTGetProperty(entryP, "reg", (void **)&reg_prop, &prop_size) == kSuccess) {
				ml_init_arm_debug_interface(args, ml_io_map(gSocPhys + *reg_prop, *(reg_prop + 1)));
			}
#if DEVELOPMENT || DEBUG
			// When args != NULL, this means we're being called from arm_init on the boot CPU.
			// This controls one-time initialization of the Panic Trace infrastructure

			simple_lock_init(&panic_trace_lock, 0); //assuming single threaded mode

			// Panic_halt is deprecated. Please use panic_trace istead.
			unsigned int temp_bootarg_panic_trace;
			if (PE_parse_boot_argn("panic_trace", &temp_bootarg_panic_trace, sizeof(temp_bootarg_panic_trace)) ||
			    PE_parse_boot_argn("panic_halt", &temp_bootarg_panic_trace, sizeof(temp_bootarg_panic_trace))) {
				kprintf("pe_arm_init_debug: panic_trace=%d\n", temp_bootarg_panic_trace);

				// Prepare debug command buffers.
				pe_init_debug_command(entryP, &cpu_halt, "cpu_halt");
				pe_init_debug_command(entryP, &enable_trace, "enable_trace");
				pe_init_debug_command(entryP, &enable_alt_trace, "enable_alt_trace");
				pe_init_debug_command(entryP, &trace_halt, "trace_halt");

				// now that init's are done, enable the panic halt capture (allows pe_init_debug_command to panic normally if necessary)
				bootarg_panic_trace = temp_bootarg_panic_trace;

				// start tracing now if enabled
				PE_arm_debug_enable_trace();
			}
#endif
		}
	} else {
		kprintf("pe_arm_init_debug: failed to find cpu-debug-interface\n");
	}
}

static uint32_t
pe_arm_map_interrupt_controller(void)
{
	DTEntry         entryP;
	uintptr_t       *reg_prop;
	uint32_t        prop_size;
	vm_offset_t     soc_phys = 0;

	gSocPhys = pe_arm_get_soc_base_phys();

	soc_phys = gSocPhys;
	kprintf("pe_arm_map_interrupt_controller: soc_phys:  0x%lx\n", (unsigned long)soc_phys);
	if (soc_phys == 0) {
		return 0;
	}

	if (DTFindEntry("interrupt-controller", "master", &entryP) == kSuccess) {
		kprintf("pe_arm_map_interrupt_controller: found interrupt-controller\n");
		DTGetProperty(entryP, "reg", (void **)&reg_prop, &prop_size);
		gPicBase = ml_io_map(soc_phys + *reg_prop, *(reg_prop + 1));
		kprintf("pe_arm_map_interrupt_controller: gPicBase: 0x%lx\n", (unsigned long)gPicBase);
	}
	if (gPicBase == 0) {
		kprintf("pe_arm_map_interrupt_controller: failed to find the interrupt-controller.\n");
		return 0;
	}

	if (DTFindEntry("device_type", "timer", &entryP) == kSuccess) {
		kprintf("pe_arm_map_interrupt_controller: found timer\n");
		DTGetProperty(entryP, "reg", (void **)&reg_prop, &prop_size);
		gTimerBase = ml_io_map(soc_phys + *reg_prop, *(reg_prop + 1));
		kprintf("pe_arm_map_interrupt_controller: gTimerBase: 0x%lx\n", (unsigned long)gTimerBase);
	}
	if (gTimerBase == 0) {
		kprintf("pe_arm_map_interrupt_controller: failed to find the timer.\n");
		return 0;
	}

	return 1;
}

uint32_t
pe_arm_init_interrupts(void *args)
{
	kprintf("pe_arm_init_interrupts: args: %p\n", args);

	/* Set up mappings for interrupt controller and possibly timers (if they haven't been set up already) */
	if (args != NULL) {
		if (!pe_arm_map_interrupt_controller()) {
			return 0;
		}
	}

	return pe_arm_init_timer(args);
}

static uint32_t
pe_arm_init_timer(void *args)
{
	vm_offset_t     pic_base = 0;
	vm_offset_t     timer_base = 0;
	vm_offset_t     soc_phys;
	vm_offset_t     eoi_addr = 0;
	uint32_t        eoi_value = 0;
	struct tbd_ops  generic_funcs = {&fleh_fiq_generic, NULL, NULL};
	tbd_ops_t       tbd_funcs = &generic_funcs;

	/* The SoC headers expect to use pic_base, timer_base, etc... */
	pic_base = gPicBase;
	timer_base = gTimerBase;
	soc_phys = gSocPhys;

#if defined(ARM_BOARD_CLASS_S5L8960X)
	if (!strcmp(gPESoCDeviceType, "s5l8960x-io")) {
		tbd_funcs = &s5l8960x_funcs;
	} else
#endif
#if defined(ARM_BOARD_CLASS_T7000)
	if (!strcmp(gPESoCDeviceType, "t7000-io") ||
	    !strcmp(gPESoCDeviceType, "t7001-io")) {
		tbd_funcs = &t7000_funcs;
	} else
#endif
#if defined(ARM_BOARD_CLASS_S7002)
	if (!strcmp(gPESoCDeviceType, "s7002-io")) {
#ifdef ARM_BOARD_WFE_TIMEOUT_NS
		// Enable the WFE Timer
		rPMGR_EVENT_TMR_PERIOD = ((uint64_t)(ARM_BOARD_WFE_TIMEOUT_NS) *gPEClockFrequencyInfo.timebase_frequency_hz) / NSEC_PER_SEC;
		rPMGR_EVENT_TMR = rPMGR_EVENT_TMR_PERIOD;
		rPMGR_EVENT_TMR_CTL = PMGR_EVENT_TMR_CTL_EN;
#endif /* ARM_BOARD_WFE_TIMEOUT_NS */

		rPMGR_INTERVAL_TMR = 0x7FFFFFFF;
		rPMGR_INTERVAL_TMR_CTL = PMGR_INTERVAL_TMR_CTL_EN | PMGR_INTERVAL_TMR_CTL_CLR_INT;

		eoi_addr = timer_base;
		eoi_value = PMGR_INTERVAL_TMR_CTL_EN | PMGR_INTERVAL_TMR_CTL_CLR_INT;
		tbd_funcs = &s7002_funcs;
	} else
#endif
#if defined(ARM_BOARD_CLASS_S8000)
	if (!strcmp(gPESoCDeviceType, "s8000-io") ||
	    !strcmp(gPESoCDeviceType, "s8001-io")) {
		tbd_funcs = &s8000_funcs;
	} else
#endif
#if defined(ARM_BOARD_CLASS_T8002)
	if (!strcmp(gPESoCDeviceType, "t8002-io") ||
	    !strcmp(gPESoCDeviceType, "t8004-io")) {
		/* Enable the Decrementer */
		aic_write32(kAICTmrCnt, 0x7FFFFFFF);
		aic_write32(kAICTmrCfg, kAICTmrCfgEn);
		aic_write32(kAICTmrIntStat, kAICTmrIntStatPct);
#ifdef ARM_BOARD_WFE_TIMEOUT_NS
		// Enable the WFE Timer
		rPMGR_EVENT_TMR_PERIOD = ((uint64_t)(ARM_BOARD_WFE_TIMEOUT_NS) *gPEClockFrequencyInfo.timebase_frequency_hz) / NSEC_PER_SEC;
		rPMGR_EVENT_TMR = rPMGR_EVENT_TMR_PERIOD;
		rPMGR_EVENT_TMR_CTL = PMGR_EVENT_TMR_CTL_EN;
#endif /* ARM_BOARD_WFE_TIMEOUT_NS */

		eoi_addr = pic_base;
		eoi_value = kAICTmrIntStatPct;
		tbd_funcs = &t8002_funcs;
	} else
#endif
#if defined(ARM_BOARD_CLASS_T8010)
	if (!strcmp(gPESoCDeviceType, "t8010-io")) {
		tbd_funcs = &t8010_funcs;
	} else
#endif
#if defined(ARM_BOARD_CLASS_T8011)
	if (!strcmp(gPESoCDeviceType, "t8011-io")) {
		tbd_funcs = &t8011_funcs;
	} else
#endif
#if defined(ARM_BOARD_CLASS_T8015)
	if (!strcmp(gPESoCDeviceType, "t8015-io")) {
		tbd_funcs = &t8015_funcs;
	} else
#endif
#if defined(ARM_BOARD_CLASS_BCM2837)
	if (!strcmp(gPESoCDeviceType, "bcm2837-io")) {
		tbd_funcs = &bcm2837_funcs;
	} else
#endif
	return 0;

	if (args != NULL) {
		ml_init_timebase(args, tbd_funcs, eoi_addr, eoi_value);
	}

	return 1;
}
