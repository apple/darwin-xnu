/*
 * Coyright (c) 2005-2015 Apple Computer, Inc. All rights reserved.
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

/* 
 * For arm32 ABI where 64-bit types are aligned to even registers and
 * 64-bits on stack, we need to unpack registers differently. So
 * we use the mungers for that. Currently this is just ARMv7k.
 *
 * Since arm32 has no need for munging otherwise, we don't include
 * any of this for other arm32 ABIs
 */
#if __arm__ && (__BIGGEST_ALIGNMENT__ > 4)

#include <sys/munge.h>
#include <sys/param.h>
#include <mach/thread_status.h>
#include <libkern/libkern.h>
#include <stdint.h>


/* 
 * Userspace args are in r0-r6, then r8, then stack unless this is an
 * indirect call in which case the syscall number is in r0 then args
 * are in registers r1-r6, then r8, then stack. This is for mach and
 * BSD style syscalls.
 */


#define SS_TO_STYLE(ss)                            ((ss->r[12] != 0) ? kDirect : kIndirect)
#define REGS_TO_STYLE(regs)                        (SS_TO_STYLE(((const arm_saved_state_t *)regs)))

typedef enum {
	kIndirect = 0,
	kDirect
} style_t;

#define DECLARE_AND_CAST(regs, args, ss, uu_args)  const arm_saved_state_t *ss = (const arm_saved_state_t *)regs; \
                                                   uint32_t *uu_args = (uint32_t *)args;

/* 
 * We start 32 bytes after sp since 4 registers are pushed onto the stack
 * in the userspace syscall handler, and the first 4 stack argumnets are moved 
 * into registers already
 */
#define ARG_SP_BYTE_OFFSET                         32


/*
 * Marshal in arguments from userspace where no padding exists
 */

static int
marshal_no_pad(const arm_saved_state_t *ss, uint32_t *args, const uint32_t word_count)
{
	int error = 0;
	/* init assuming kDirect style */
	uint32_t copy_count, contiguous_reg_count = 7, contiguous_reg_start = 0;
	style_t style = SS_TO_STYLE(ss);

	if (style == kIndirect) {
		contiguous_reg_count--;
		contiguous_reg_start++;
	}

	/* r0 through r6 */
	copy_count = MIN(word_count, contiguous_reg_count);
	memcpy(args, &(ss->r[contiguous_reg_start]), copy_count * sizeof(uint32_t));
	args += copy_count;

	if (word_count > copy_count) {
		/* r8 */
		*args = ss->r[8];
		args++;
		copy_count++;

		/* stack */
		if (word_count > copy_count) {
			error = copyin(ss->sp + ARG_SP_BYTE_OFFSET,
				    args, (word_count - copy_count) * sizeof(uint32_t));
			if (error)
				return error;
		}
	}
	return error;
}

/*
 * Define mungers to marshal userspace data into argument structs
 */

int
munge_w(const void *regs, void *args)
{
	return marshal_no_pad(regs, args, 1);
}

int 
munge_ww(const void *regs, void *args)
{
	return marshal_no_pad(regs, args, 2);
}

int 
munge_www(const void *regs, void *args)
{
	return marshal_no_pad(regs, args, 3);
}

int 
munge_wwww(const void *regs, void *args)
{
	return marshal_no_pad(regs, args, 4);
}

int 
munge_wwwww(const void *regs, void *args)
{
	return marshal_no_pad(regs, args, 5);
}

int 
munge_wwwwww(const void *regs, void *args)
{
	return marshal_no_pad(regs, args, 6);
}

int 
munge_wwwwwww(const void *regs, void *args)
{
	return marshal_no_pad(regs, args, 7);
}

int 
munge_wwwwwwww(const void *regs, void *args)
{
	return marshal_no_pad(regs, args, 8);
}

int 
munge_wwl(const void *regs, void *args)
{
	if (REGS_TO_STYLE(regs) == kDirect)
		return marshal_no_pad(regs, args, 3);
	else {
		DECLARE_AND_CAST(regs, args, ss, uu_args);

		uu_args[0] = ss->r[1]; // w
		uu_args[1] = ss->r[2]; // w
		uu_args[2] = ss->r[4]; // l (longs are aligned to even registers for armv7k, so skip r3)
		uu_args[3] = ss->r[5]; // 
		return 0;
	}
}

int 
munge_wwlw(const void *regs, void *args)
{
	if (REGS_TO_STYLE(regs) == kDirect)
		return marshal_no_pad(regs, args, 5);
	else {
		DECLARE_AND_CAST(regs, args, ss, uu_args);

		int error = munge_wwl(regs, args); // wwl
		uu_args[4] = ss->r[6]; // w
		return error;
	}
}

int
munge_wwlww(const void *regs, void *args)
{
	if (REGS_TO_STYLE(regs) == kDirect)
		// the long-long here is aligned on an even register
		// so there shouldn't be any padding
		return marshal_no_pad(regs, args, 6);
	else {
		DECLARE_AND_CAST(regs, args, ss, uu_args);

		int error = munge_wwlw(regs, args); // wwlw
		uu_args[5] = ss->r[8]; // w
		return error;
	}
}

int 
munge_wwlll(const void *regs, void *args)
{
	if (REGS_TO_STYLE(regs) == kDirect)
		return marshal_no_pad(regs, args, 8);
	else {
		DECLARE_AND_CAST(regs, args, ss, uu_args);

		int error = munge_wwl(regs, args);  // wwl
		if (error)
			return error;
		uu_args[4] = ss->r[6];              // l
		uu_args[5] = ss->r[8];              //
		return copyin(ss->sp + ARG_SP_BYTE_OFFSET, // l
			   &(uu_args[6]), 2 * sizeof(uint32_t));
	}
}

int
munge_wwllww(const void *regs, void *args)
{
	return munge_wwlll(regs, args);
}

int
munge_wl(const void *regs, void *args)
{
	if (REGS_TO_STYLE(regs) == kDirect)
		memcpy(args, regs, 4 * sizeof(uint32_t));
	else {
		DECLARE_AND_CAST(regs, args, ss, uu_args);

		uu_args[0] = ss->r[1]; // w
		uu_args[2] = ss->r[2]; // l
		uu_args[3] = ss->r[3]; //
	}
	return 0;
}

int
munge_wlw(const void *regs, void *args)
{
	if (REGS_TO_STYLE(regs) == kDirect)
		memcpy(args, regs, 5 * sizeof(uint32_t));	
	else {
		DECLARE_AND_CAST(regs, args, ss, uu_args);

		uu_args[0] = ss->r[1]; // w
		uu_args[2] = ss->r[2]; // l
		uu_args[3] = ss->r[3]; //
		uu_args[4] = ss->r[4]; // w
	}
	return 0;
}

int
munge_wlww(const void *regs, void *args)
{
	if (REGS_TO_STYLE(regs) == kDirect)
		memcpy(args, regs, 6 * sizeof(uint32_t));
	else {
		DECLARE_AND_CAST(regs, args, ss, uu_args);

		uu_args[0] = ss->r[1]; // w
		uu_args[2] = ss->r[2]; // l
		uu_args[3] = ss->r[3]; //
		uu_args[4] = ss->r[4]; // w
		uu_args[5] = ss->r[5]; // w
	}
	return 0;
}

int
munge_wlwwwll(const void *regs, void *args)
{
	DECLARE_AND_CAST(regs, args, ss, uu_args);

	if (REGS_TO_STYLE(regs) == kDirect) {
		memcpy(args, regs, 7 * sizeof(uint32_t)); // wlwww
		return copyin(ss->sp + ARG_SP_BYTE_OFFSET,       // ll
			   uu_args + 8, 4 * sizeof(uint32_t));
	}
	else {
		uu_args[0] = ss->r[1];                    // w
		uu_args[2] = ss->r[2];                    // l
		uu_args[3] = ss->r[3];                    // 
		uu_args[4] = ss->r[4];                    // w
		uu_args[5] = ss->r[5];                    // w
		uu_args[6] = ss->r[6];                    // w
		return copyin(ss->sp + ARG_SP_BYTE_OFFSET,       // ll
			   uu_args + 8, 4 * sizeof(uint32_t));
	}
}

int
munge_wlwwwllw(const void *regs, void *args)
{
	DECLARE_AND_CAST(regs, args, ss, uu_args);

	if (REGS_TO_STYLE(regs) == kDirect) {
		memcpy(args, regs, 7 * sizeof(uint32_t)); // wlwww
		return copyin(ss->sp + ARG_SP_BYTE_OFFSET,
			   uu_args + 8, 5 * sizeof(uint32_t)); // ll
	}
	else {
		uu_args[0] = ss->r[1];                    // w
		uu_args[2] = ss->r[2];                    // l
		uu_args[3] = ss->r[3];                    // 
		uu_args[4] = ss->r[4];                    // w
		uu_args[5] = ss->r[5];                    // w
		uu_args[6] = ss->r[6];                    // w
		return copyin(ss->sp + ARG_SP_BYTE_OFFSET,       // llw
			   uu_args + 8, 5 * sizeof(uint32_t));
	}
}

int 
munge_wlwwlwlw(const void *regs, void *args)
{
	DECLARE_AND_CAST(regs, args, ss, uu_args);

	if (REGS_TO_STYLE(regs) == kDirect)
		uu_args[0] = ss->r[0];      // w
	else
		uu_args[0] = ss->r[1];      // w

	uu_args[2] = ss->r[2];              // l
	uu_args[3] = ss->r[3];              //
	uu_args[4] = ss->r[4];              // w
	uu_args[5] = ss->r[5];              // w
	uu_args[6] = ss->r[6];              // l
	uu_args[7] = ss->r[8];              //
	return copyin(ss->sp + ARG_SP_BYTE_OFFSET, // wlw
		   uu_args + 8, 5 * sizeof(uint32_t));
}

int 
munge_wll(const void *regs, void *args)
{
	if (REGS_TO_STYLE(regs) == kDirect)
		memcpy(args, regs, 6 * sizeof(uint32_t));	
	else {
		DECLARE_AND_CAST(regs, args, ss, uu_args);

		uu_args[0] = ss->r[1]; // w
		uu_args[2] = ss->r[2]; // l
		uu_args[3] = ss->r[3]; //
		uu_args[4] = ss->r[4]; // l
		uu_args[5] = ss->r[5]; //
	}
	return 0;
}

int 
munge_wlll(const void *regs, void *args)
{
	DECLARE_AND_CAST(regs, args, ss, uu_args);

	int error = munge_wll(regs, args); // wll
	uu_args[6] = ss->r[6]; // l
	uu_args[7] = ss->r[8]; //
	return error;
}

int 
munge_wllll(const void *regs, void *args)
{
	DECLARE_AND_CAST(regs, args, ss, uu_args);

	munge_wlll(regs, args);             // wlll
	return copyin(ss->sp + ARG_SP_BYTE_OFFSET, // l
		   uu_args + 8, 2 * sizeof(uint32_t));
}

int
munge_wllww(const void *regs, void *args)
{
	return munge_wlll(regs, args);
}

int 
munge_wllwwll(const void *regs, void *args)
{
	DECLARE_AND_CAST(regs, args, ss, uu_args);

	int error = munge_wlll(regs, args); // wllww
	if (error)
		return error;
	return copyin(ss->sp + ARG_SP_BYTE_OFFSET, // ll
		   uu_args + 8, 4 * sizeof(uint32_t));
}

int 
munge_wwwlw(const void *regs, void *args)
{
	if (REGS_TO_STYLE(regs) == kDirect)
		memcpy(args, regs, 7 * sizeof(uint32_t));
	else {
		DECLARE_AND_CAST(regs, args, ss, uu_args);

		uu_args[0] = ss->r[1]; // w
		uu_args[1] = ss->r[2]; // w
		uu_args[2] = ss->r[3]; // w
		uu_args[4] = ss->r[4]; // l
		uu_args[5] = ss->r[5]; //
		uu_args[6] = ss->r[6]; // w
	}
	return 0;
}

int
munge_wwwlww(const void *regs, void *args)
{
	if (REGS_TO_STYLE(regs) == kDirect)
		return munge_wlll(regs, args);
	else {
		DECLARE_AND_CAST(regs, args, ss, uu_args);

		uu_args[0] = ss->r[1]; // w
		uu_args[1] = ss->r[2]; // w
		uu_args[2] = ss->r[3]; // w
		uu_args[4] = ss->r[4]; // l
		uu_args[5] = ss->r[5]; //
		uu_args[6] = ss->r[6]; // w
		uu_args[7] = ss->r[8]; // w
		return 0;
	}
}
	
int 
munge_wwwl(const void *regs, void *args)
{
	if (REGS_TO_STYLE(regs) == kDirect)
		return munge_wll(regs, args);
	else {
		DECLARE_AND_CAST(regs, args, ss, uu_args);

		uu_args[0] = ss->r[1]; // w
		uu_args[1] = ss->r[2]; // w
		uu_args[2] = ss->r[3]; // w
		uu_args[4] = ss->r[4]; // l
		uu_args[5] = ss->r[5]; //
		return 0;
	}
}

int 
munge_wwwwl(const void *regs, void *args)
{
	if (REGS_TO_STYLE(regs) == kDirect)
		return marshal_no_pad(regs, args, 6);
	else {
		DECLARE_AND_CAST(regs, args, ss, uu_args);

		uu_args[0] = ss->r[1]; // w
		uu_args[1] = ss->r[2]; // w
		uu_args[2] = ss->r[3]; // w
		uu_args[3] = ss->r[4]; // w
		uu_args[4] = ss->r[6]; // l
		uu_args[5] = ss->r[8]; //
		return 0;
	}
}

int
munge_wwwwlw(const void *regs, void *args)
{
	if (REGS_TO_STYLE(regs) == kDirect)
		return marshal_no_pad(regs, args, 7);
	else {
		DECLARE_AND_CAST(regs, args, ss, uu_args);

		int error = munge_wwwwl(regs, args); // wwwwl
		if (error)
			return error;
		return copyin(ss->sp + ARG_SP_BYTE_OFFSET, // w
			   uu_args + 6, sizeof(uint32_t));
	}
}

int 
munge_wwwwwl(const void *regs, void *args)
{
	if (REGS_TO_STYLE(regs) == kDirect)
		return munge_wlll(regs, args);
	else {
		DECLARE_AND_CAST(regs, args, ss, uu_args);

		uu_args[0] = ss->r[1]; // w
		uu_args[1] = ss->r[2]; // w
		uu_args[2] = ss->r[3]; // w
		uu_args[3] = ss->r[4]; // w
		uu_args[4] = ss->r[5]; // w
		uu_args[6] = ss->r[6]; // l
		uu_args[7] = ss->r[8]; //
		return 0;
	}
}

int 
munge_wwwwwlww(const void *regs, void *args)
{
	if (REGS_TO_STYLE(regs) == kDirect)
		return munge_wllll(regs, args);
	else {
		DECLARE_AND_CAST(regs, args, ss, uu_args);

		int error = munge_wwwwwl(regs, args); // wwwwwl
		if (error)
			return error;
		return copyin(ss->sp + ARG_SP_BYTE_OFFSET, // ww
			   uu_args + 8, 2 * sizeof(uint32_t));
	}
}

int
munge_wwwwwllw(const void *regs, void *args)
{
	DECLARE_AND_CAST(regs, args, ss, uu_args);

	int error = munge_wwwwwl(regs, args); // wwwwwl
	if (error)
		return error;
	return copyin(ss->sp + ARG_SP_BYTE_OFFSET, // lw
		   uu_args + 8, 3 * sizeof(uint32_t));
}

int
munge_wwwwwlll(const void *regs, void *args)
{
	DECLARE_AND_CAST(regs, args, ss, uu_args);
	int error;

	if (REGS_TO_STYLE(regs) == kDirect) {
		error = munge_wlll(regs, args);     // wlll
		if (error)
			return error;
		return copyin(ss->sp + ARG_SP_BYTE_OFFSET, // ll
			   uu_args + 8, 4 * sizeof(uint32_t));
	}
	else {
		error = munge_wwwwwl(regs, args);   // wwwwwl
		if (error)
			return error;
		return copyin(ss->sp + ARG_SP_BYTE_OFFSET, // ll
			   uu_args + 8, 4 * sizeof(uint32_t));
	}
}

int
munge_wwwwwwl(const void *regs, void *args)
{
	munge_wwlll(regs, args);

	if (REGS_TO_STYLE(regs) == kDirect)
		return marshal_no_pad(regs, args, 8);
	else {
		DECLARE_AND_CAST(regs, args, ss, uu_args);

		memcpy(args, &(ss->r[1]), 6 * sizeof(uint32_t)); // wwwwww
		return copyin(ss->sp + ARG_SP_BYTE_OFFSET,       // l
			   &(uu_args[6]), 2 * sizeof(uint32_t));
	}
}

int 
munge_wwwwwwlw(const void *regs, void *args)
{
	if (REGS_TO_STYLE(regs) == kDirect)
		return marshal_no_pad(regs, args, 9);
	else {
		DECLARE_AND_CAST(regs, args, ss, uu_args);

		memcpy(args, &(ss->r[1]), 6 * sizeof(uint32_t)); // wwwwww
		return copyin(ss->sp + ARG_SP_BYTE_OFFSET,       // lw
			   &(uu_args[6]), 3 * sizeof(uint32_t));
	}
}
	
int 
munge_wwwwwwll(const void *regs, void *args)
{
	if (REGS_TO_STYLE(regs) == kDirect)
		return marshal_no_pad(regs, args, 10);
	else {
		DECLARE_AND_CAST(regs, args, ss, uu_args);

		memcpy(args, &(ss->r[1]), 6 * sizeof(uint32_t)); // wwwwww
		return copyin(ss->sp + ARG_SP_BYTE_OFFSET,       // ll
			   &(uu_args[6]), 4 * sizeof(uint32_t));
	}
}

int 
munge_wsw(const void *regs, void *args)
{
	return munge_wlw(regs, args);
}

int 
munge_wws(const void *regs, void *args)
{
	return munge_wwl(regs, args);
}

int
munge_wwws(const void *regs, void *args)
{
	return munge_wwwl(regs, args);
}

int
munge_wwwsw(const void *regs, void *args)
{
	return munge_wwwlw(regs, args);
}

int 
munge_llllll(const void *regs, void *args)
{
	if (REGS_TO_STYLE(regs) == kDirect)
		return marshal_no_pad(regs, args, 12);
	else {
		DECLARE_AND_CAST(regs, args, ss, uu_args);

		uu_args[0]  = ss->r[2];             // l
		uu_args[1]  = ss->r[3];             //
		uu_args[2]  = ss->r[4];             // l
		uu_args[3]  = ss->r[5];             //
		uu_args[4]  = ss->r[6];             // l
		uu_args[5]  = ss->r[8];             //
		return copyin(ss->sp + ARG_SP_BYTE_OFFSET, // lll
			   uu_args + 6, 6 * sizeof(uint32_t));
	}
}

int 
munge_ll(const void *regs, void *args)
{
	if (REGS_TO_STYLE(regs) == kDirect)
		return marshal_no_pad(regs, args, 4);
	else
		memcpy(args, (const uint32_t*)regs + 2, 4 * sizeof(uint32_t));
	return 0;
}

int 
munge_l(const void *regs, void *args)
{
	if (REGS_TO_STYLE(regs) == kDirect)
		return marshal_no_pad(regs, args, 2);
	else
		memcpy(args, (const uint32_t*)regs + 2, 2 * sizeof(uint32_t));
	return 0;
}

int 
munge_lw(const void *regs, void *args)
{
	if (REGS_TO_STYLE(regs) == kDirect)
		return marshal_no_pad(regs, args, 3);
	else
		memcpy(args, (const uint32_t*)regs + 2, 3 * sizeof(uint32_t));
	return 0;
}

int
munge_lwww(const void *regs, void *args)
{
	if (REGS_TO_STYLE(regs) == kDirect)
		return marshal_no_pad(regs, args, 5);
	else
		memcpy(args, (const uint32_t*)regs + 2, 5 * sizeof(uint32_t));
	return 0;
}

int 
munge_lwwwwwww(const void *regs, void *args)
{
	if (REGS_TO_STYLE(regs) == kDirect)
		return marshal_no_pad(regs, args, 9);
	else {
		DECLARE_AND_CAST(regs, args, ss, uu_args);

		uu_args[0]  = ss->r[2];             // l
		uu_args[1]  = ss->r[3];             // 
		uu_args[2]  = ss->r[4];             // w
		uu_args[3]  = ss->r[5];             // w
		uu_args[4]  = ss->r[6];             // w
		uu_args[5]  = ss->r[8];             // w
		return copyin(ss->sp + ARG_SP_BYTE_OFFSET, // www
			   uu_args + 6, 3 * sizeof(uint32_t));
	}
}

int
munge_wwlwww(const void *regs, void *args)
{
	if (REGS_TO_STYLE(regs) == kDirect)
		return marshal_no_pad(regs, args, 7);
	else {
		DECLARE_AND_CAST(regs, args, ss, uu_args);

		uu_args[0]  = ss->r[1];             // w
		uu_args[1]  = ss->r[2];             // w
		uu_args[2]  = ss->r[4];             // l
		uu_args[3]  = ss->r[5];             //
		uu_args[4]  = ss->r[6];             // w
		uu_args[5]  = ss->r[8];             // w
		return copyin(ss->sp + ARG_SP_BYTE_OFFSET, // w
			   uu_args + 6, sizeof(uint32_t));
	}
		
}

int
munge_wlwwwl(const void *regs, void *args)
{
	DECLARE_AND_CAST(regs, args, ss, uu_args);

	if (REGS_TO_STYLE(regs) == kDirect) {
		memcpy(args, regs,  7 * sizeof(uint32_t)); // wlwww
		return copyin(ss->sp + ARG_SP_BYTE_OFFSET, //  l
			   uu_args + 8, 2 * sizeof(uint32_t));
	} else {
		uu_args[0]  = ss->r[1];             // w
		uu_args[2]  = ss->r[2];             // l
		uu_args[3]  = ss->r[3];             //
		uu_args[4]  = ss->r[4];             // w
		uu_args[5]  = ss->r[5];             // w
		uu_args[6]  = ss->r[6];             // w
		return copyin(ss->sp + ARG_SP_BYTE_OFFSET, // l
			   uu_args + 8, 2 * sizeof(uint32_t));
	}
}

int
munge_wwlwwwl(const void *regs, void *args)
{
        DECLARE_AND_CAST(regs, args, ss, uu_args);

	if (REGS_TO_STYLE(regs) == kDirect) {
		memcpy(args, regs,  7 * sizeof(uint32_t)); // wwlwww
		return copyin(ss->sp + ARG_SP_BYTE_OFFSET, //  l
			   uu_args + 8, 2 * sizeof(uint32_t));
	} else {
		uu_args[0]  = ss->r[1];             // w
		uu_args[1]  = ss->r[2];             // w
		uu_args[2]  = ss->r[4];             // l
		uu_args[3]  = ss->r[5];             //
		uu_args[4]  = ss->r[6];             // w
		uu_args[5]  = ss->r[8];             // w
		return copyin(ss->sp + ARG_SP_BYTE_OFFSET, // wl
			   uu_args + 6, 4 * sizeof(uint32_t));
	}
}

#endif // __arm__ && (__BIGGEST_ALIGNMENT__ > 4)
