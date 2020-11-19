/*
 * Copyright (c) 2019 Apple Computer, Inc. All rights reserved.
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

#pragma once

extern "C" {
#include <machine/machine_routines.h>
};

#include <IOKit/IOService.h>

/*!
 * @class      IOPMGR
 * @abstract   The base class for power managers, such as ApplePMGR.
 */
class IOPMGR : public IOService
{
	OSDeclareAbstractStructors(IOPMGR);

public:
	/*!
	 * @function      enableCPUCore
	 * @abstract      Enable a single CPU core.
	 * @discussion    Release a secondary CPU core from reset, and enable
	 *                external IRQ delivery to the core.  XNU will not
	 *                invoke this method on the boot CPU's cpu_id.
	 * @param cpu_id  Logical CPU ID of the core.
	 */
	virtual void enableCPUCore(unsigned int cpu_id) = 0;

	/*!
	 * @function      disableCPUCore
	 * @abstract      Disable a single CPU core.
	 * @discussion    Prepare a secondary CPU core for power down, and
	 *                disable external IRQ delivery to the core.  XNU
	 *                will not invoke this method on the boot CPU's cpu_id.
	 *                Note that the enable and disable operations are not
	 *                symmetric, as disableCPUCore doesn't actually cut
	 *                power to the core.
	 * @param cpu_id  Logical CPU ID of the core.
	 */
	virtual void disableCPUCore(unsigned int cpu_id) = 0;

	/*!
	 * @function          enableCPUCluster
	 * @abstract          Enable power to a cluster of CPUs.
	 * @discussion        Called to power up a CPU cluster if the cluster-wide
	 *                    voltage rails are disabled (i.e. PIO to the cluster
	 *                    isn't even working).
	 * @param cluster_id  Cluster ID.
	 */
	virtual void enableCPUCluster(unsigned int cluster_id) = 0;

	/*!
	 * @function          disableCPUCluster
	 * @abstract          Disable power to a cluster of CPUs.
	 * @discussion        Called to disable the voltage rails on a CPU
	 *                    cluster.  This will only be invoked if all CPUs
	 *                    in the cluster are already disabled.  It is
	 *                    presumed that after this operation completes,
	 *                    PIO operations to the cluster will cause a
	 *                    fatal bus error.
	 * @param cluster_id  Cluster ID.
	 */
	virtual void disableCPUCluster(unsigned int cluster_id) = 0;

	/*!
	 * @function                   initCPUIdle
	 * @abstract                   Initialize idle-related parameters.
	 * @param info                 Pointer to the ml_processor_info_t struct that is
	 *                             being initialized (and hasn't been registered yet).
	 */
	virtual void initCPUIdle(ml_processor_info_t *info) = 0;

	/*!
	 * @function                   enterCPUIdle
	 * @abstract                   Called from cpu_idle() prior to entering the idle state on
	 *                             the current CPU.
	 * @param newIdleTimeoutTicks  If non-NULL, will be overwritten with a new idle timeout value,
	 *                             in ticks.  If the value is 0, XNU will disable the idle timer.
	 */
	virtual void enterCPUIdle(UInt64 *newIdleTimeoutTicks) = 0;

	/*!
	 * @function                   exitCPUIdle
	 * @abstract                   Called from cpu_idle_exit() after leaving the idle state on
	 *                             the current CPU.
	 * @param newIdleTimeoutTicks  If non-NULL, will be overwritten with a new idle timeout value,
	 *                             in ticks.  If the value is 0, XNU will disable the idle timer.
	 */
	virtual void exitCPUIdle(UInt64 *newIdleTimeoutTicks) = 0;

	/*!
	 * @function                   updateCPUIdle
	 * @abstract                   Called from timer_intr() to ask when to schedule the next idle
	 *                             timeout on the current CPU.
	 * @param newIdleTimeoutTicks  If non-NULL, will be overwritten with a new idle timeout value,
	 *                             in ticks.  If the value is 0, XNU will disable the idle timer.
	 */
	virtual void updateCPUIdle(UInt64 *newIdleTimeoutTicks) = 0;
};
