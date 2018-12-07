/*
 * Copyright (c) 2007 Apple Inc. All rights reserved.
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
#include <debug.h>
#include <mach/mach_types.h>
#include <mach/kern_return.h>
#include <mach/thread_status.h>
#include <kern/thread.h>
#include <kern/kalloc.h>
#include <arm/vmparam.h>
#include <arm/cpu_data_internal.h>
#include <arm/proc_reg.h>

struct arm_vfpv2_state
{
        __uint32_t        __r[32];
        __uint32_t        __fpscr;

};

typedef struct arm_vfpv2_state	arm_vfpv2_state_t;

#define	ARM_VFPV2_STATE_COUNT ((mach_msg_type_number_t) \
	(sizeof (arm_vfpv2_state_t)/sizeof(uint32_t)))


/*
 * Forward definitions
 */
void
                thread_set_child(thread_t child, int pid);

void
                thread_set_parent(thread_t parent, int pid);

/*
 * Maps state flavor to number of words in the state:
 */
/* __private_extern__ */
unsigned int    _MachineStateCount[] = {
	 /* FLAVOR_LIST */ 0,
	ARM_THREAD_STATE_COUNT,
	ARM_VFP_STATE_COUNT,
	ARM_EXCEPTION_STATE_COUNT,
	ARM_DEBUG_STATE_COUNT
};

extern zone_t ads_zone;

kern_return_t
machine_thread_state_convert_to_user(
			 __unused thread_t thread,
			 __unused thread_flavor_t flavor,
			 __unused thread_state_t tstate,
			 __unused mach_msg_type_number_t *count)
{
	// No conversion to userspace representation on this platform
	return KERN_SUCCESS;
}

kern_return_t
machine_thread_state_convert_from_user(
			 __unused thread_t thread,
			 __unused thread_flavor_t flavor,
			 __unused thread_state_t tstate,
			 __unused mach_msg_type_number_t count)
{
	// No conversion from userspace representation on this platform
	return KERN_SUCCESS;
}

kern_return_t
machine_thread_siguctx_pointer_convert_to_user(
			 __unused thread_t thread,
			 __unused user_addr_t *uctxp)
{
	// No conversion to userspace representation on this platform
	return KERN_SUCCESS;
}

kern_return_t
machine_thread_function_pointers_convert_from_user(
			 __unused thread_t thread,
			 __unused user_addr_t *fptrs,
			 __unused uint32_t count)
{
	// No conversion from userspace representation on this platform
	return KERN_SUCCESS;
}

/*
 * Routine:	machine_thread_get_state
 *
 */
kern_return_t
machine_thread_get_state(
			 thread_t thread,
			 thread_flavor_t flavor,
			 thread_state_t tstate,
			 mach_msg_type_number_t * count)
{

#define machine_thread_get_state_kprintf(x...)	/* kprintf("machine_thread_get
						 * _state: " x) */

	switch (flavor) {
	case THREAD_STATE_FLAVOR_LIST:
		if (*count < 4)
			return (KERN_INVALID_ARGUMENT);

		tstate[0] = ARM_THREAD_STATE;
		tstate[1] = ARM_VFP_STATE;
		tstate[2] = ARM_EXCEPTION_STATE;
		tstate[3] = ARM_DEBUG_STATE;
		*count = 4;
		break;

	case ARM_THREAD_STATE:{
			struct arm_thread_state *state;
			struct arm_saved_state *saved_state;
			arm_unified_thread_state_t *unified_state;

			unsigned int    i;
			if (*count < ARM_THREAD_STATE_COUNT)
				return (KERN_INVALID_ARGUMENT);

			if (*count == ARM_UNIFIED_THREAD_STATE_COUNT) {
				unified_state = (arm_unified_thread_state_t *) tstate;
				state = &unified_state->ts_32;
				unified_state->ash.flavor = ARM_THREAD_STATE32;
				unified_state->ash.count = ARM_THREAD_STATE32_COUNT;
			} else {
				state = (struct arm_thread_state *) tstate;
			}
			saved_state = &thread->machine.PcbData;

			state->sp = saved_state->sp;
			state->lr = saved_state->lr;
			state->pc = saved_state->pc;
			state->cpsr = saved_state->cpsr;
			for (i = 0; i < 13; i++)
				state->r[i] = saved_state->r[i];
			machine_thread_get_state_kprintf("machine_thread_get_state: pc 0x%x r0 0x%x sp  0x%x\n",
					 state->pc, state->r[0], state->sp);

			if (*count != ARM_UNIFIED_THREAD_STATE_COUNT) {
				*count = ARM_THREAD_STATE_COUNT;
			}
			break;
		}
	case ARM_EXCEPTION_STATE:{
			struct arm_exception_state *state;
			struct arm_saved_state *saved_state;

			if (*count < ARM_EXCEPTION_STATE_COUNT)
				return (KERN_INVALID_ARGUMENT);

			state = (struct arm_exception_state *) tstate;
			saved_state = &thread->machine.PcbData;

			state->exception = saved_state->exception;
			state->fsr = saved_state->fsr;
			state->far = saved_state->far;

			*count = ARM_EXCEPTION_STATE_COUNT;
			break;
		}
	case ARM_VFP_STATE:{
#if	__ARM_VFP__
			struct arm_vfp_state *state;
			struct arm_vfpsaved_state *saved_state;
			unsigned int    i;
			unsigned int	max;

			if (*count < ARM_VFP_STATE_COUNT) {
				if (*count < ARM_VFPV2_STATE_COUNT)
					return (KERN_INVALID_ARGUMENT);
				else
					*count =  ARM_VFPV2_STATE_COUNT;
			}

			if (*count ==  ARM_VFPV2_STATE_COUNT)
				max = 32;
			else
				max = 64;

			state = (struct arm_vfp_state *) tstate;
			saved_state = find_user_vfp(thread);

			state->fpscr = saved_state->fpscr;
			for (i = 0; i < max; i++)
				state->r[i] = saved_state->r[i];

#endif
			break;
		}
	case ARM_DEBUG_STATE:{
			arm_debug_state_t *state;
			arm_debug_state_t *thread_state;

                        if (*count < ARM_DEBUG_STATE_COUNT)
				return (KERN_INVALID_ARGUMENT);
			
                        state = (arm_debug_state_t *) tstate;
                        thread_state = find_debug_state(thread);
                        
                        if (thread_state == NULL)
				bzero(state, sizeof(arm_debug_state_t));
                        else
				bcopy(thread_state, state, sizeof(arm_debug_state_t));
			
                        *count = ARM_DEBUG_STATE_COUNT;
                        break;
		}

	default:
		return (KERN_INVALID_ARGUMENT);
	}
	return (KERN_SUCCESS);
}


/*
 * Routine:	machine_thread_get_kern_state
 *
 */
kern_return_t
machine_thread_get_kern_state(
			      thread_t thread,
			      thread_flavor_t flavor,
			      thread_state_t tstate,
			      mach_msg_type_number_t * count)
{

#define machine_thread_get_kern_state_kprintf(x...)	/* kprintf("machine_threa
							 * d_get_kern_state: "
							 * x) */

	/*
	 * This works only for an interrupted kernel thread
	 */
	if (thread != current_thread() || getCpuDatap()->cpu_int_state == NULL)
		return KERN_FAILURE;

	switch (flavor) {
	case ARM_THREAD_STATE:{
			struct arm_thread_state *state;
			struct arm_saved_state *saved_state;
			unsigned int    i;
			if (*count < ARM_THREAD_STATE_COUNT)
				return (KERN_INVALID_ARGUMENT);

			state = (struct arm_thread_state *) tstate;
			saved_state = getCpuDatap()->cpu_int_state;

			state->sp = saved_state->sp;
			state->lr = saved_state->lr;
			state->pc = saved_state->pc;
			state->cpsr = saved_state->cpsr;
			for (i = 0; i < 13; i++)
				state->r[i] = saved_state->r[i];
			machine_thread_get_kern_state_kprintf("machine_thread_get_state: pc 0x%x r0 0x%x sp  0x%x\n",
					 state->pc, state->r[0], state->sp);
			*count = ARM_THREAD_STATE_COUNT;
			break;
		}
	default:
		return (KERN_INVALID_ARGUMENT);
	}
	return (KERN_SUCCESS);
}

extern long long arm_debug_get(void);

/*
 * Routine:	machine_thread_set_state
 *
 */
kern_return_t
machine_thread_set_state(
			 thread_t thread,
			 thread_flavor_t flavor,
			 thread_state_t tstate,
			 mach_msg_type_number_t count)
{

#define machine_thread_set_state_kprintf(x...)	/* kprintf("machine_thread_set
						 * _state: " x) */

	switch (flavor) {
	case ARM_THREAD_STATE:{
			struct arm_thread_state *state;
			struct arm_saved_state *saved_state;
			arm_unified_thread_state_t *unified_state;
			int             old_psr;

			if (count < ARM_THREAD_STATE_COUNT)
				return (KERN_INVALID_ARGUMENT);

			if (count == ARM_UNIFIED_THREAD_STATE_COUNT) {
				unified_state = (arm_unified_thread_state_t *) tstate;
				state = &unified_state->ts_32;
			} else {
				state = (struct arm_thread_state *) tstate;
			}
			saved_state = &thread->machine.PcbData;
			old_psr = saved_state->cpsr;
			memcpy((char *) saved_state, (char *) state, sizeof(*state));
			/*
			 * do not allow privileged bits of the PSR to be
			 * changed
			 */
			saved_state->cpsr = (saved_state->cpsr & ~PSR_USER_MASK) | (old_psr & PSR_USER_MASK);

			machine_thread_set_state_kprintf("machine_thread_set_state: pc 0x%x r0 0x%x sp 0x%x\n",
					 state->pc, state->r[0], state->sp);
			break;
		}
	case ARM_VFP_STATE:{
#if __ARM_VFP__
			struct arm_vfp_state *state;
			struct arm_vfpsaved_state *saved_state;
			unsigned int    i;
			unsigned int	max;

			if (count < ARM_VFP_STATE_COUNT) {
				if (count < ARM_VFPV2_STATE_COUNT)
					return (KERN_INVALID_ARGUMENT);
				else
					count =  ARM_VFPV2_STATE_COUNT;
			}

			if (count ==  ARM_VFPV2_STATE_COUNT)
				max = 32;
			else
				max = 64;

			state = (struct arm_vfp_state *) tstate;
			saved_state = find_user_vfp(thread);

			saved_state->fpscr = state->fpscr;
			for (i = 0; i < max; i++)
				saved_state->r[i] = state->r[i];

#endif
			break;
		}
	case ARM_EXCEPTION_STATE:{

			if (count < ARM_EXCEPTION_STATE_COUNT)
				return (KERN_INVALID_ARGUMENT);

			break;
		}
	case ARM_DEBUG_STATE:{
			arm_debug_state_t *state;
			arm_debug_state_t *thread_state;
                        boolean_t enabled = FALSE;
			unsigned int    i;

                        if (count < ARM_DEBUG_STATE_COUNT)
				return (KERN_INVALID_ARGUMENT);

                        state = (arm_debug_state_t *) tstate;
                        thread_state = find_debug_state(thread);

			if (count < ARM_DEBUG_STATE_COUNT)
				return (KERN_INVALID_ARGUMENT);
			
                        for (i = 0; i < 16; i++) {
				/* do not allow context IDs to be set */
				if (((state->bcr[i] & ARM_DBGBCR_TYPE_MASK) != ARM_DBGBCR_TYPE_IVA)
				    || ((state->bcr[i] & ARM_DBG_CR_LINKED_MASK) != ARM_DBG_CR_LINKED_UNLINKED)
				    || ((state->wcr[i] & ARM_DBGBCR_TYPE_MASK) != ARM_DBGBCR_TYPE_IVA)
				    || ((state->wcr[i] & ARM_DBG_CR_LINKED_MASK) != ARM_DBG_CR_LINKED_UNLINKED)) {
					return KERN_PROTECTION_FAILURE;
				}
				if ((((state->bcr[i] & ARM_DBG_CR_ENABLE_MASK) == ARM_DBG_CR_ENABLE_ENABLE))
				    || ((state->wcr[i] & ARM_DBG_CR_ENABLE_MASK) == ARM_DBG_CR_ENABLE_ENABLE)) {
					enabled = TRUE;
				}
                        }
			
                        if (!enabled) {
				if (thread_state != NULL)
				{
                                        void *pTmp = thread->machine.DebugData;
                                        thread->machine.DebugData = NULL;
                                        zfree(ads_zone, pTmp);
				}
                        }
                        else
                        {
				if (thread_state == NULL)
					thread_state = zalloc(ads_zone);
				
				for (i = 0; i < 16; i++) {
					/* set appropriate priviledge; mask out unknown bits */
					thread_state->bcr[i] = (state->bcr[i] & (ARM_DBG_CR_ADDRESS_MASK_MASK
										     | ARM_DBGBCR_MATCH_MASK
										     | ARM_DBG_CR_BYTE_ADDRESS_SELECT_MASK
										     | ARM_DBG_CR_ENABLE_MASK))
						| ARM_DBGBCR_TYPE_IVA
						| ARM_DBG_CR_LINKED_UNLINKED
						| ARM_DBG_CR_SECURITY_STATE_BOTH
						| ARM_DBG_CR_MODE_CONTROL_USER;
					thread_state->bvr[i] = state->bvr[i] & ARM_DBG_VR_ADDRESS_MASK;
					thread_state->wcr[i] = (state->wcr[i] & (ARM_DBG_CR_ADDRESS_MASK_MASK
										     | ARM_DBGWCR_BYTE_ADDRESS_SELECT_MASK
										     | ARM_DBGWCR_ACCESS_CONTROL_MASK
										     | ARM_DBG_CR_ENABLE_MASK))
						| ARM_DBG_CR_LINKED_UNLINKED
						| ARM_DBG_CR_SECURITY_STATE_BOTH
						| ARM_DBG_CR_MODE_CONTROL_USER;                                
					thread_state->wvr[i] = state->wvr[i] & ARM_DBG_VR_ADDRESS_MASK;
				}
				
				if (thread->machine.DebugData == NULL)
					thread->machine.DebugData = thread_state;
                        }
			
                        if (thread == current_thread()) {
                                arm_debug_set(thread_state);
			}
			
			break;
		}
        
	default:
		return (KERN_INVALID_ARGUMENT);
	}
	return (KERN_SUCCESS);
}

/*
 * Routine:	machine_thread_state_initialize
 *
 */
kern_return_t
machine_thread_state_initialize(
				thread_t thread)
{
	struct arm_saved_state *savestate;

	savestate = (struct arm_saved_state *) & thread->machine.PcbData;
	bzero((char *) savestate, sizeof(struct arm_saved_state));
	savestate->cpsr = PSR_USERDFLT;

#if __ARM_VFP__
	vfp_state_initialize(&thread->machine.uVFPdata);
	vfp_state_initialize(&thread->machine.kVFPdata);
#endif

	thread->machine.DebugData = NULL;

	return KERN_SUCCESS;
}

#if __ARM_VFP__
void
vfp_state_initialize(struct arm_vfpsaved_state *vfp_state)
{
	/* Set default VFP state to RunFast mode:
	*
	* - flush-to-zero mode
	* - default NaN mode
	* - no enabled exceptions
	*
	* On the VFP11, this allows the use of floating point without
	* trapping to support code, which we do not provide.  With
	* the Cortex-A8, this allows the use of the (much faster) NFP
	* pipeline for single-precision operations.
	*/

	bzero(vfp_state, sizeof(*vfp_state));
	vfp_state->fpscr = FPSCR_DEFAULT;
}
#endif /* __ARM_VFP__ */


/*
 * Routine:	machine_thread_dup
 *
 */
kern_return_t
machine_thread_dup(
		   thread_t self,
		   thread_t target,
		   __unused boolean_t is_corpse)
{
	struct arm_saved_state *self_saved_state;
	struct arm_saved_state *target_saved_state;

#if	__ARM_VFP__
	struct arm_vfpsaved_state *self_vfp_state;
	struct arm_vfpsaved_state *target_vfp_state;
#endif

	target->machine.cthread_self = self->machine.cthread_self;
	target->machine.cthread_data = self->machine.cthread_data;

	self_saved_state = &self->machine.PcbData;
	target_saved_state = &target->machine.PcbData;
	bcopy(self_saved_state, target_saved_state, sizeof(struct arm_saved_state));

#if	__ARM_VFP__
	self_vfp_state = &self->machine.uVFPdata;
	target_vfp_state = &target->machine.uVFPdata;
	bcopy(self_vfp_state, target_vfp_state, sizeof(struct arm_vfpsaved_state));
#endif

	return (KERN_SUCCESS);
}

/*
 * Routine:	get_user_regs
 *
 */
struct arm_saved_state *
get_user_regs(
	      thread_t thread)
{
	return (&thread->machine.PcbData);
}

/*
 * Routine:	find_user_regs
 *
 */
struct arm_saved_state *
find_user_regs(
	       thread_t thread)
{
	return get_user_regs(thread);
}

/*
 * Routine:	find_kern_regs
 *
 */
struct arm_saved_state *
find_kern_regs(
	       thread_t thread)
{
	/*
         * This works only for an interrupted kernel thread
         */
	if (thread != current_thread() || getCpuDatap()->cpu_int_state == NULL)
		return ((struct arm_saved_state *) NULL);
	else
		return (getCpuDatap()->cpu_int_state);

}

#if __ARM_VFP__
/*
 *	Find the user state floating point context.  If there is no user state context,
 *	we just return a 0.
 */

struct arm_vfpsaved_state *
find_user_vfp(
	      thread_t thread)
{
	return &thread->machine.uVFPdata;
}
#endif /* __ARM_VFP__ */

arm_debug_state_t *
find_debug_state(
             thread_t thread)
{
       return thread->machine.DebugData;
}

/*
 * Routine:	thread_userstack
 *
 */
kern_return_t
thread_userstack(
		 __unused thread_t thread,
		 int flavor,
		 thread_state_t tstate,
		 unsigned int count,
		 mach_vm_offset_t * user_stack,
		 int *customstack,
		 __unused boolean_t is64bit
)
{

	switch (flavor) {
	case ARM_THREAD_STATE:
		{
			struct arm_thread_state *state;


			if (count < ARM_THREAD_STATE_COUNT)
				return (KERN_INVALID_ARGUMENT);

			if (customstack)
				*customstack = 0;
			state = (struct arm_thread_state *) tstate;

			if (state->sp) {
				*user_stack = CAST_USER_ADDR_T(state->sp);
				if (customstack)
					*customstack = 1;
			} else {
				*user_stack = CAST_USER_ADDR_T(USRSTACK);
			}
		}
		break;

	default:
		return (KERN_INVALID_ARGUMENT);
	}

	return (KERN_SUCCESS);
}

/*
 * thread_userstackdefault:
 *
 * Return the default stack location for the
 * thread, if otherwise unknown.
 */
kern_return_t
thread_userstackdefault(
	mach_vm_offset_t *default_user_stack,
	boolean_t is64bit __unused)
{
	*default_user_stack = USRSTACK;

	return (KERN_SUCCESS);
}

/*
 * Routine:	thread_setuserstack
 *
 */
void
thread_setuserstack(thread_t thread, mach_vm_address_t user_stack)
{
	struct arm_saved_state *sv;

#define thread_setuserstack_kprintf(x...)	/* kprintf("thread_setuserstac
						 * k: " x) */

	sv = get_user_regs(thread);

	sv->sp = user_stack;

	thread_setuserstack_kprintf("stack %x\n", sv->sp);

	return;
}

/*
 * Routine:	thread_adjuserstack
 *
 */
uint64_t
thread_adjuserstack(thread_t thread, int adjust)
{
	struct arm_saved_state *sv;

	sv = get_user_regs(thread);

	sv->sp += adjust;

	return sv->sp;
}

/*
 * Routine:	thread_setentrypoint
 *
 */
void
thread_setentrypoint(thread_t thread, mach_vm_offset_t entry)
{
	struct arm_saved_state *sv;

#define thread_setentrypoint_kprintf(x...)	/* kprintf("thread_setentrypoi
						 * nt: " x) */

	sv = get_user_regs(thread);

	sv->pc = entry;

	thread_setentrypoint_kprintf("entry %x\n", sv->pc);

	return;
}

/*
 * Routine:	thread_entrypoint
 *
 */
kern_return_t
thread_entrypoint(
		  __unused thread_t thread,
		  int flavor,
		  thread_state_t tstate,
		  __unused unsigned int count,
		  mach_vm_offset_t * entry_point
)
{
	switch (flavor) {
	case ARM_THREAD_STATE:
		{
			struct arm_thread_state *state;

			state = (struct arm_thread_state *) tstate;

			/*
			 * If a valid entry point is specified, use it.
			 */
			if (state->pc) {
				*entry_point = CAST_USER_ADDR_T(state->pc);
			} else {
				*entry_point = CAST_USER_ADDR_T(VM_MIN_ADDRESS);
			}
		}
		break;

	default:
		return (KERN_INVALID_ARGUMENT);
	}

	return (KERN_SUCCESS);
}


/*
 * Routine:	thread_set_child
 *
 */
void
thread_set_child(
		 thread_t child,
		 int pid)
{
	struct arm_saved_state *child_state;

	child_state = get_user_regs(child);

	child_state->r[0] = (uint_t) pid;
	child_state->r[1] = 1ULL;
}


/*
 * Routine:	thread_set_parent
 *
 */
void
thread_set_parent(
		  thread_t parent,
		  int pid)
{
	struct arm_saved_state *parent_state;

	parent_state = get_user_regs(parent);

	parent_state->r[0] = pid;
	parent_state->r[1] = 0;
}


struct arm_act_context {
	struct arm_saved_state ss;
#if __ARM_VFP__
	struct arm_vfpsaved_state vfps;
#endif
};

/*
 * Routine:	act_thread_csave
 *
 */
void           *
act_thread_csave(void)
{
	struct arm_act_context *ic;
	kern_return_t   kret;
	unsigned int    val;

	ic = (struct arm_act_context *) kalloc(sizeof(struct arm_act_context));

	if (ic == (struct arm_act_context *) NULL)
		return ((void *) 0);

	val = ARM_THREAD_STATE_COUNT;
	kret = machine_thread_get_state(current_thread(),
					ARM_THREAD_STATE,
					(thread_state_t) & ic->ss,
					&val);
	if (kret != KERN_SUCCESS) {
		kfree(ic, sizeof(struct arm_act_context));
		return ((void *) 0);
	}
#if __ARM_VFP__
	val = ARM_VFP_STATE_COUNT;
	kret = machine_thread_get_state(current_thread(),
					ARM_VFP_STATE,
					(thread_state_t) & ic->vfps,
					&val);
	if (kret != KERN_SUCCESS) {
		kfree(ic, sizeof(struct arm_act_context));
		return ((void *) 0);
	}
#endif
	return (ic);
}

/*
 * Routine:	act_thread_catt
 *
 */
void
act_thread_catt(void *ctx)
{
	struct arm_act_context *ic;
	kern_return_t   kret;

	ic = (struct arm_act_context *) ctx;

	if (ic == (struct arm_act_context *) NULL)
		return;

	kret = machine_thread_set_state(current_thread(),
					ARM_THREAD_STATE,
					(thread_state_t) & ic->ss,
					ARM_THREAD_STATE_COUNT);
	if (kret != KERN_SUCCESS)
		goto out;

#if __ARM_VFP__
	kret = machine_thread_set_state(current_thread(),
					ARM_VFP_STATE,
					(thread_state_t) & ic->vfps,
					ARM_VFP_STATE_COUNT);
	if (kret != KERN_SUCCESS)
		goto out;
#endif
out:
	kfree(ic, sizeof(struct arm_act_context));
}

/*
 * Routine:	act_thread_catt
 *
 */
void 
act_thread_cfree(void *ctx)
{
	kfree(ctx, sizeof(struct arm_act_context));
}

kern_return_t
thread_set_wq_state32(thread_t thread, thread_state_t tstate)
{
	arm_thread_state_t *state;
	struct arm_saved_state *saved_state;
	thread_t curth = current_thread();
	spl_t s=0;

	saved_state = &thread->machine.PcbData;
	state = (arm_thread_state_t *)tstate;

	if (curth != thread) {
		s = splsched();
		thread_lock(thread);
	}

	/*
	 * do not zero saved_state, it can be concurrently accessed
	 * and zero is not a valid state for some of the registers,
	 * like sp.
	 */
	thread_state32_to_saved_state(state, saved_state);
	saved_state->cpsr = PSR_USERDFLT;

	if (curth != thread) {
		thread_unlock(thread);
		splx(s);
	}

	return KERN_SUCCESS;
}
