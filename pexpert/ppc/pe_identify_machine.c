/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
#include <pexpert/protos.h>
#include <pexpert/pexpert.h>
#include <pexpert/ppc/powermac.h>
#include <pexpert/device_tree.h>

/* pe_identify_machine:
 *
 *   Sets up platform parameters.
 *   Returns:    nothing
 */
void pe_identify_machine(void)
{
  DTEntry       cpu, root;
  unsigned long *value;
  int           size;

  // Clear the gPEClockFrequencyInfo struct
  bzero((void *)&gPEClockFrequencyInfo, sizeof(clock_frequency_info_t));
  
  // Start with default values.
  gPEClockFrequencyInfo.timebase_frequency_hz = 25000000;
  gPEClockFrequencyInfo.bus_clock_rate_hz     = 100000000;
  gPEClockFrequencyInfo.cpu_clock_rate_hz     = 300000000;

  // Try to get the values from the device tree.
  if (DTFindEntry("device_type", "cpu", &cpu) == kSuccess) {
    // Find the time base frequency first.
    if (DTGetProperty(cpu, "timebase-frequency", (void **)&value, &size) == kSuccess) {
      // timebase_frequency_hz is only 32 bits, and the device tree should never provide 64 bits
      // so this if should never be taken.
      if (size == 8) gPEClockFrequencyInfo.timebase_frequency_hz = *(unsigned long long *)value;
      else gPEClockFrequencyInfo.timebase_frequency_hz = *value;
    }
    gPEClockFrequencyInfo.dec_clock_rate_hz = gPEClockFrequencyInfo.timebase_frequency_hz;
    
    // Find the bus frequency next.  Try the cpu node, then the root.
    if (DTGetProperty(cpu, "bus-frequency", (void **)&value, &size) == kSuccess) {
      if (size == 8) gPEClockFrequencyInfo.bus_frequency_hz = *(unsigned long long *)value;
      else gPEClockFrequencyInfo.bus_frequency_hz = *value;
    } else {
      if (DTLookupEntry(0, "/", &root) == kSuccess) {
	if (DTGetProperty(root, "clock-frequency", (void **)&value, &size) == kSuccess) {
	  if (size == 8) gPEClockFrequencyInfo.bus_frequency_hz = *(unsigned long long *)value;
	  else gPEClockFrequencyInfo.bus_frequency_hz = *value;
	}
      }
    }
    
    gPEClockFrequencyInfo.bus_frequency_min_hz = gPEClockFrequencyInfo.bus_frequency_hz;
    gPEClockFrequencyInfo.bus_frequency_max_hz = gPEClockFrequencyInfo.bus_frequency_hz;
    
    if (gPEClockFrequencyInfo.bus_frequency_hz < 0x100000000ULL)
      gPEClockFrequencyInfo.bus_clock_rate_hz = gPEClockFrequencyInfo.bus_frequency_hz;
    else
      gPEClockFrequencyInfo.bus_clock_rate_hz = 0xFFFFFFFF;
    
    // Find the cpu frequency last.
    if (DTGetProperty(cpu, "clock-frequency", (void **)&value, &size) == kSuccess) {
      if (size == 8) gPEClockFrequencyInfo.cpu_frequency_hz = *(unsigned long long *)value;
      else gPEClockFrequencyInfo.cpu_frequency_hz = *value;
    }
    
    gPEClockFrequencyInfo.cpu_frequency_min_hz = gPEClockFrequencyInfo.cpu_frequency_hz;
    gPEClockFrequencyInfo.cpu_frequency_max_hz = gPEClockFrequencyInfo.cpu_frequency_hz;
    
    if (gPEClockFrequencyInfo.cpu_frequency_hz < 0x100000000ULL)
      gPEClockFrequencyInfo.cpu_clock_rate_hz = gPEClockFrequencyInfo.cpu_frequency_hz;
    else
      gPEClockFrequencyInfo.cpu_clock_rate_hz = 0xFFFFFFFF;
  }
  
  // Set the num / den pairs form the hz values.
  gPEClockFrequencyInfo.timebase_frequency_num = gPEClockFrequencyInfo.timebase_frequency_hz;
  gPEClockFrequencyInfo.timebase_frequency_den = 1;
  
  gPEClockFrequencyInfo.bus_clock_rate_num = gPEClockFrequencyInfo.bus_clock_rate_hz;
  gPEClockFrequencyInfo.bus_clock_rate_den = 1;
  
  gPEClockFrequencyInfo.bus_to_cpu_rate_num =
    (2 * gPEClockFrequencyInfo.cpu_clock_rate_hz) / gPEClockFrequencyInfo.bus_clock_rate_hz;
  gPEClockFrequencyInfo.bus_to_cpu_rate_den = 2;
  
  gPEClockFrequencyInfo.bus_to_dec_rate_num = 1;
  gPEClockFrequencyInfo.bus_to_dec_rate_den =
    gPEClockFrequencyInfo.bus_clock_rate_hz / gPEClockFrequencyInfo.dec_clock_rate_hz;
}

/* get_io_base_addr():
 *
 *   Get the base address of the io controller.  
 */
vm_offset_t get_io_base_addr(void)
{
  DTEntry     entryP;
  vm_offset_t *address;
  int         size;
  
  if ((DTFindEntry("device_type", "dbdma", &entryP) == kSuccess)
      || (DTFindEntry("device_type", "mac-io", &entryP) == kSuccess))
    {
      if (DTGetProperty(entryP, "AAPL,address", (void **)&address, &size) == kSuccess)
	return *address;
      
      if (DTGetProperty(entryP, "assigned-addresses", (void **)&address, &size) == kSuccess)
	// address calculation not correct
	return *(address+2);
    }
  
  panic("Can't find this machine's io base address\n");
  return 0;
}

vm_offset_t PE_find_scc(void)
{
	vm_offset_t io, sccadd;
	DTEntry     entryP;
	vm_offset_t *sccregs;
	unsigned int sccrsize;
	
	if(!(io = get_io_base_addr())) {		/* Get the I/O controller base address */
		return (vm_offset_t)0;				/* Hmmm, no I/O??? What gives??? How'd we even boot? */
	}

	
/*	Note: if we find a escc-legacy, we need to kind of hack because it can be either an offset
	into the iobase or the actual address itself.  ORint the two should provide the correct 
	for either */

	sccadd = 0;								/* Assume none for now */

	if(DTFindEntry("name", "escc-legacy", &entryP) == kSuccess)	{	/* Find the old fashioned serial port */
		if (DTGetProperty(entryP, "reg", (void **)&sccregs, &sccrsize) == kSuccess) {	/* Do we have some registers? */
			sccadd = ((vm_offset_t)*sccregs | io);	/* Get the address */
		}
	}
	
	if(DTFindEntry("name", "escc", &entryP) == kSuccess) {	/* Well, see if we just have the new fangled one */
		sccadd = io + 0x12000; 				/* Yeah, but still return the oldie goldie... */
	}
	
	return sccadd;							/* Return it if you found it */
}

unsigned int PE_init_taproot(vm_offset_t *taddr)
{
	DTEntry     entryP;
	vm_offset_t *tappdata;
	unsigned int tappsize;
	
	
	if(DTFindEntry("name", "memory-map", &entryP) != kSuccess) return 0;	/* no memory map */

	if (DTGetProperty(entryP, "TapRoot", (void **)&tappdata, &tappsize) != kSuccess) return 0;	/* No TapRoot */

	tappdata[1] = (tappdata[1] + 4095 ) & -4096;	/* Make sure this is a whole page */

	*taddr = io_map_spec(tappdata[0], tappdata[1]);		/* Map it in and return the address */
	tappdata[0] = *taddr;					/* Also change property */
	return tappdata[1];						/* And the size */
}
