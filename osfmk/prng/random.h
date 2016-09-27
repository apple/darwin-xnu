/*
 * Copyright (c) 2013 Apple Inc. All rights reserved.
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

#ifndef	_PRNG_RANDOM_H_
#define	_PRNG_RANDOM_H_

__BEGIN_DECLS

#ifdef XNU_KERNEL_PRIVATE

#define	ENTROPY_BUFFER_BYTE_SIZE	64

#define	ENTROPY_BUFFER_SIZE		ENTROPY_BUFFER_BYTE_SIZE/sizeof(uint32_t)

typedef struct entropy_data {
	uint32_t	*index_ptr;
	uint32_t	buffer[ENTROPY_BUFFER_SIZE];
} entropy_data_t;

extern entropy_data_t EntropyData;

/* Trace codes for DBG_SEC_KERNEL: */
#define ENTROPY_READ(n)	SECURITYDBG_CODE(DBG_SEC_KERNEL, n) /* n: 0 .. 3 */

/*
 * Early_random implementation params: */
#define	EARLY_RANDOM_SEED_SIZE		(16)
#define	EARLY_RANDOM_STATE_STATIC_SIZE	(264)

#if defined (__x86_64__)
#define current_prng_context()	(current_cpu_datap()->cpu_prng)
#define master_prng_context()	(cpu_datap(master_cpu)->cpu_prng)
#else
#error architecture unknown
#endif

#include <corecrypto/ccdrbg.h>
#include <corecrypto/ccsha1.h>

typedef struct	ccdrbg_info ccdrbg_info_t;
typedef void  (*ccdrbg_factory_t)(ccdrbg_info_t *info, const void *custom);

extern void	ccdrbg_factory_yarrow(ccdrbg_info_t *info, const void *custom);

void		prng_factory_register(ccdrbg_factory_t factory);
void		prng_cpu_init(int cpu);

void		entropy_buffer_read(char *buffer, unsigned int *count);
void		entropy_boot_trace(void);

/*
 * Wrapper for requesting a CCDRBG operation.
 * This macro makes the DRBG call with pre-emption disabled to ensure that
 * any attempt to block will cause a panic. And the operation is timed and
 * cannot exceed 10msec (for development kernels).
 * But skip this while we retain Yarrow.
 */
#define YARROW 1
#if YARROW
#define PRNG_CCDRBG(op)					\
MACRO_BEGIN						\
	op;						\
MACRO_END
#else
#define PRNG_CCDRBG(op)					\
MACRO_BEGIN						\
	uint64_t	start;				\
	uint64_t	stop;				\
	disable_preemption();				\
	start = mach_absolute_time();			\
	op;						\
	stop = mach_absolute_time();			\
	enable_preemption();				\
	assert(stop - start < 10*NSEC_PER_MSEC ||	\
	       machine_timeout_suspended());		\
	(void) start;					\
	(void) stop;					\
MACRO_END
#endif

#endif /* XNU_KERNEL_PRIVATE */

/* /dev/random's PRNG is reseeded after generating this many bytes: */
#define	RESEED_BYTES (17597)

__END_DECLS

#endif /* _PRNG_RANDOM_H_ */
