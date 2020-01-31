/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
 */

#ifndef _BSD_ARM_REBOOT_H_
#define _BSD_ARM_REBOOT_H_

/*
 * Empty file (publicly)
 */

#include <sys/appleapiopts.h>

#ifdef  BSD_KERNEL_PRIVATE

/*
 *	Use most significant 16 bits to avoid collisions with
 *	machine independent flags.
 */
#define RB_POWERDOWN    0x00010000      /* power down on halt */
#define RB_NOBOOTRC     0x00020000      /* don't run '/etc/rc.boot' */
#define RB_DEBUG        0x00040000      /* drop into mini monitor on panic */
#define RB_EJECT        0x00080000      /* eject disks on halt */
#define RB_COMMAND      0x00100000      /* new boot command specified */
#define RB_NOFP         0x00200000      /* don't use floating point */
#define RB_BOOTNEXT     0x00400000      /* reboot into NeXT */
#define RB_BOOTDOS      0x00800000      /* reboot into DOS */
#define RB_PRETTY       0x01000000      /* shutdown with pretty graphics */

#endif  /* BSD_KERNEL_PRIVATE */

#endif  /* _BSD_ARM_REBOOT_H_ */
