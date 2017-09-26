/*
 * Copyright (c) 2014 Apple Inc. All rights reserved.
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

#include <IOKit/IOInterruptAccountingPrivate.h>
#include <IOKit/IOKernelReporters.h>

uint32_t gInterruptAccountingStatisticBitmask =
#if !defined(__arm__)
	/* Disable timestamps for older ARM platforms; they are expensive. */
	IA_GET_ENABLE_BIT(kInterruptAccountingFirstLevelTimeIndex) |
	IA_GET_ENABLE_BIT(kInterruptAccountingSecondLevelCPUTimeIndex) |
	IA_GET_ENABLE_BIT(kInterruptAccountingSecondLevelSystemTimeIndex) |
#endif
	IA_GET_ENABLE_BIT(kInterruptAccountingFirstLevelCountIndex) |
	IA_GET_ENABLE_BIT(kInterruptAccountingSecondLevelCountIndex);

IOLock * gInterruptAccountingDataListLock = NULL;
queue_head_t gInterruptAccountingDataList;

void interruptAccountingInit(void)
{
	int bootArgValue = 0;

	if (PE_parse_boot_argn("interrupt_accounting", &bootArgValue, sizeof(bootArgValue)))
                gInterruptAccountingStatisticBitmask = bootArgValue;

	gInterruptAccountingDataListLock = IOLockAlloc();

	assert(gInterruptAccountingDataListLock);

	queue_init(&gInterruptAccountingDataList);
}

void interruptAccountingDataAddToList(IOInterruptAccountingData * data)
{
	IOLockLock(gInterruptAccountingDataListLock);
	queue_enter(&gInterruptAccountingDataList, data, IOInterruptAccountingData *, chain); 
	IOLockUnlock(gInterruptAccountingDataListLock);
}

void interruptAccountingDataRemoveFromList(IOInterruptAccountingData * data)
{
	IOLockLock(gInterruptAccountingDataListLock);
	queue_remove(&gInterruptAccountingDataList, data, IOInterruptAccountingData *, chain); 
	IOLockUnlock(gInterruptAccountingDataListLock);
}

void interruptAccountingDataUpdateChannels(IOInterruptAccountingData * data, IOSimpleReporter * reporter)
{
	uint64_t i = 0;

	for (i = 0; i < IA_NUM_INTERRUPT_ACCOUNTING_STATISTICS; i++) {
		if (IA_GET_STATISTIC_ENABLED(i))
		reporter->setValue(IA_GET_CHANNEL_ID(data->interruptIndex, i), data->interruptStatistics[i]);
	}
}

void interruptAccountingDataInheritChannels(IOInterruptAccountingData * data, IOSimpleReporter * reporter)
{
	uint64_t i = 0;

	for (i = 0; i < IA_NUM_INTERRUPT_ACCOUNTING_STATISTICS; i++) {
		if (IA_GET_STATISTIC_ENABLED(i))
		data->interruptStatistics[i] = reporter->getValue(IA_GET_CHANNEL_ID(data->interruptIndex, i));
	}
}

