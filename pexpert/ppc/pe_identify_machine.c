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
#include <pexpert/protos.h>
#include <pexpert/pexpert.h>
#include <pexpert/ppc/powermac.h>
#include <pexpert/device_tree.h>

/* External declarations */

unsigned int LockTimeOut = 12500000;

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
  gPEClockFrequencyInfo.bus_clock_rate_hz = 100000000;
  gPEClockFrequencyInfo.cpu_clock_rate_hz = 300000000;
  gPEClockFrequencyInfo.dec_clock_rate_hz =  25000000;
  
  // Try to get the values from the device tree.
  if (DTFindEntry("device_type", "cpu", &cpu) == kSuccess) {
    if (DTGetProperty(cpu, "bus-frequency",
		      (void **)&value, &size) == kSuccess)
      gPEClockFrequencyInfo.bus_clock_rate_hz = *value;
    else {
      if (DTLookupEntry(0, "/", &root) == kSuccess)
	if (DTGetProperty(root, "clock-frequency",
			  (void **)&value, &size) == kSuccess)
	  gPEClockFrequencyInfo.bus_clock_rate_hz = *value;
    }
    
    if (DTGetProperty(cpu, "clock-frequency",
		      (void **)&value, &size) == kSuccess)
      gPEClockFrequencyInfo.cpu_clock_rate_hz = *value;
    
    if (DTGetProperty(cpu, "timebase-frequency",
		      (void **)&value, &size) == kSuccess)
      gPEClockFrequencyInfo.dec_clock_rate_hz = *value;
  }
  
  // Set the num / den pairs form the hz values.
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

boolean_t PE_init_ethernet_debugger(void)
{
  boolean_t result;
#if 0
  DTEntry       entryP;
  vm_offset_t   *address;
  unsigned char *netAddr;
  int           size;
  vm_offset_t   io;
  
  if ((io = get_io_base_addr())
      && (DTFindEntry("name", "mace", &entryP) == kSuccess)
      && (DTGetProperty(entryP, "local-mac-address", (void **)&netAddr, &size) == kSuccess)
      && (DTGetProperty(entryP, "reg", (void **)&address, &size) == kSuccess)
      && (size == (2 * 3 * sizeof(vm_offset_t)) ))
    {
      extern boolean_t kdp_mace_init(void *baseAddresses[3],
				     unsigned char *netAddr);
      void *maceAddrs[3];
      
      // address calculation not correct
      maceAddrs[0] = (void *) io_map(io + address[0], address[1]);
      maceAddrs[1] = (void *) io_map(io + address[2], 0x1000);
      maceAddrs[2] = (void *) (((vm_offset_t)maceAddrs[1])
			       + address[4] - address[2]);
      result = kdp_mace_init( maceAddrs, netAddr );
      
    } else
#endif
      result = FALSE;
  
  return result;
}

vm_offset_t PE_find_scc(void)
{
  vm_offset_t io;
  DTEntry     entryP;
  
  if ((io = get_io_base_addr())
      && (DTFindEntry("name", "escc", &entryP) == kSuccess))
    io += 0x12000; /* Offset to legacy SCC Registers */
  else
    io = 0;
  
  return io;
}
