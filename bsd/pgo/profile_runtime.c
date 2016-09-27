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

#include <sys/sysproto.h>
#include <sys/malloc.h>
#include <sys/systm.h>
#include <sys/pgo.h>
#include <sys/kauth.h>
#include <security/mac_framework.h>
#include <libkern/OSKextLib.h>


/*
 * This tells compiler_rt not to include userspace-specific stuff writing
 * profile data to a file.
 */
int __llvm_profile_runtime = 0;


#ifdef PROFILE

/* These __llvm functions are defined in InstrProfiling.h in compiler_rt.  That
 * is a internal header, so we need to re-prototype them here.  */

uint64_t __llvm_profile_get_size_for_buffer(void);
int __llvm_profile_write_buffer(char *Buffer);
uint64_t __llvm_profile_get_size_for_buffer_internal(const char *DataBegin,
                                                     const char *DataEnd,
                                                     const char *CountersBegin,
                                                     const char *CountersEnd ,
                                                     const char *NamesBegin,
                                                     const char *NamesEnd);
int __llvm_profile_write_buffer_internal(char *Buffer,
                                         const char *DataBegin,
                                         const char *DataEnd,
                                         const char *CountersBegin,
                                         const char *CountersEnd ,
                                         const char *NamesBegin,
                                         const char *NamesEnd);

extern char __pgo_hib_DataStart __asm("section$start$__HIB$__llvm_prf_data");
extern char __pgo_hib_DataEnd   __asm("section$end$__HIB$__llvm_prf_data");
extern char __pgo_hib_NamesStart __asm("section$start$__HIB$__llvm_prf_names");
extern char __pgo_hib_NamesEnd   __asm("section$end$__HIB$__llvm_prf_names");
extern char __pgo_hib_CountersStart __asm("section$start$__HIB$__llvm_prf_cnts");
extern char __pgo_hib_CountersEnd   __asm("section$end$__HIB$__llvm_prf_cnts");


static uint64_t get_size_for_buffer(int flags)
{
        if (flags & PGO_HIB) {
                return __llvm_profile_get_size_for_buffer_internal(
                        &__pgo_hib_DataStart, &__pgo_hib_DataEnd,
                        &__pgo_hib_CountersStart, &__pgo_hib_CountersEnd,
                        &__pgo_hib_NamesStart, &__pgo_hib_NamesEnd);
        } else {
                return __llvm_profile_get_size_for_buffer();
        }
}


static int write_buffer(int flags, char *buffer)
{
        if (flags & PGO_HIB) {
                return __llvm_profile_write_buffer_internal(
                        buffer,
                        &__pgo_hib_DataStart, &__pgo_hib_DataEnd,
                        &__pgo_hib_CountersStart, &__pgo_hib_CountersEnd,
                        &__pgo_hib_NamesStart, &__pgo_hib_NamesEnd);
        } else {
                return __llvm_profile_write_buffer(buffer);
        }
}


#endif

/* this variable is used to signal to the debugger that we'd like it to reset
 * the counters */
int kdp_pgo_reset_counters = 0;

/* called in debugger context */
static kern_return_t do_pgo_reset_counters(void *context)
{
#pragma unused(context)
#ifdef PROFILE
    memset(&__pgo_hib_CountersStart, 0,
           ((uintptr_t)(&__pgo_hib_CountersEnd)) - ((uintptr_t)(&__pgo_hib_CountersStart)));
#endif
    OSKextResetPgoCounters();
    kdp_pgo_reset_counters = 0;
    return KERN_SUCCESS;
}

static kern_return_t
pgo_reset_counters()
{
    kern_return_t r;
    OSKextResetPgoCountersLock();
    kdp_pgo_reset_counters = 1;
    r = DebuggerWithCallback(do_pgo_reset_counters, NULL, FALSE);
    OSKextResetPgoCountersUnlock();
    return r;
}


/*
 * returns:
 *   EPERM  unless you are root
 *   EINVAL for invalid args.
 *   ENOSYS for not implemented
 *   ERANGE for integer overflow
 *   ENOENT if kext not found
 *   ENOTSUP kext does not support PGO
 *   EIO llvm returned an error.  shouldn't ever happen.
 */

int grab_pgo_data(struct proc *p,
                  struct grab_pgo_data_args *uap,
                  register_t *retval)
{
        char *buffer = NULL;
        int err = 0;

        (void) p;

        if (!kauth_cred_issuser(kauth_cred_get())) {
                err = EPERM;
                goto out;
        }

#if CONFIG_MACF
        err = mac_system_check_info(kauth_cred_get(), "kern.profiling_data");
        if (err) {
                goto out;
        }
#endif

        if ( uap->flags & ~PGO_ALL_FLAGS ||
             uap->size < 0 ||
             (uap->size > 0 && uap->buffer == 0))
        {
                err = EINVAL;
                goto out;
        }

        if ( uap->flags & PGO_RESET_ALL ) {
            if (uap->flags != PGO_RESET_ALL || uap->uuid || uap->buffer || uap->size ) {
                err = EINVAL;
            } else {
                kern_return_t r = pgo_reset_counters();
                switch (r) {
                case KERN_SUCCESS:
                    err = 0;
                    break;
                case KERN_OPERATION_TIMED_OUT:
                    err = ETIMEDOUT;
                    break;
                default:
                    err = EIO;
                    break;
                }
            }
            goto out;
        }

        *retval = 0;

        if (uap->uuid) {
                uuid_t uuid;
                err = copyin(uap->uuid, &uuid, sizeof(uuid));
                if (err) {
                        goto out;
                }

                if (uap->buffer == 0 && uap->size == 0) {
                    uint64_t size64;

                    if (uap->flags & PGO_WAIT_FOR_UNLOAD) {
                        err = EINVAL;
                        goto out;
                    }

                    err = OSKextGrabPgoData(uuid, &size64, NULL, 0, 0, !!(uap->flags & PGO_METADATA));
                    if (err) {
                        goto out;
                    }

                    ssize_t size = size64;
                    if ( ((uint64_t) size) != size64  ||
                         size < 0 )
                    {
                        err = ERANGE;
                        goto out;
                    }

                    *retval = size;
                    err = 0;
                    goto out;

                } else if (!uap->buffer || uap->size <= 0) {

                    err = EINVAL;
                    goto out;

                } else {

                    MALLOC(buffer, char *, uap->size, M_TEMP, M_WAITOK);
                    if (!buffer) {
                        err = ENOMEM;
                        goto out;
                    }

                    uint64_t size64;

                    err = OSKextGrabPgoData(uuid, &size64, buffer, uap->size,
                                            !!(uap->flags & PGO_WAIT_FOR_UNLOAD),
                                            !!(uap->flags & PGO_METADATA));
                    if (err) {
                        goto out;
                    }

                    ssize_t size = size64;
                    if ( ((uint64_t) size) != size64  ||
                         size < 0 )
                    {
                        err = ERANGE;
                        goto out;
                    }

                    err = copyout(buffer, uap->buffer, size);
                    if (err) {
                        goto out;
                    }

                    *retval = size;
                    goto out;
                }
        }


#ifdef PROFILE

        uint64_t size64 = get_size_for_buffer(uap->flags);
        ssize_t size = size64;

        if (uap->flags & (PGO_WAIT_FOR_UNLOAD | PGO_METADATA)) {
            err = EINVAL;
            goto out;
        }

        if ( ((uint64_t) size) != size64  ||
             size < 0 )
        {
                err = ERANGE;
                goto out;
        }


        if (uap->buffer == 0 && uap->size == 0) {
                *retval = size;
                err = 0;
                goto out;
        } else if (uap->size < size) {
                err = EINVAL;
                goto out;
        } else {
                MALLOC(buffer, char *, size, M_TEMP, M_WAITOK);
                if (!buffer) {
                        err = ENOMEM;
                        goto out;
                }

                err = write_buffer(uap->flags, buffer);
                if (err)
                {
                    err = EIO;
                    goto out;
                }

                err = copyout(buffer, uap->buffer, size);
                if (err) {
                        goto out;
                }

                *retval = size;
                goto out;
        }

#else

        *retval = -1;
        err = ENOSYS;
        goto out;

#endif

out:
        if (buffer) {
                FREE(buffer, M_TEMP);
        }
        if (err) {
                *retval = -1;
        }
        return err;
}
