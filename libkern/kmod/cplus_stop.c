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
/*
    Subtle combination of files and libraries make up the C++ runtime system for kernel modules.  We are dependant on the KernelModule kmod.make and CreateKModInfo.perl scripts to be exactly instep with both this library module and the libkmod module as well.

    If you do any maintenance on any of the following files make sure great care is taken to keep them in Sync.
    KernelModule.bproj/kmod.make
    KernelModule.bproj/CreateKModInfo.perl
    KernelModule.bproj/kmodc++/pure.c
    KernelModule.bproj/kmodc++/cplus_start.c
    KernelModule.bproj/kmodc++/cplus_start.c
    KernelModule.bproj/kmodc/c_start.c
    KernelModule.bproj/kmodc/c_stop.c

    The trick is that the linkline links all of the developers modules.  If any static constructors are used .constructors_used will be left as an undefined symbol.  This symbol is exported by the cplus_start.c routine which automatically brings in the appropriate C++ _start routine.  However the actual _start symbol is only required by the kmod_info structure that is created and initialized by the CreateKModInfo.perl script.  If no C++ was used the _start will be an undefined symbol that is finally satisfied by the c_start module in the kmod library.

    The linkline must look like this.
        *.o -lkmodc++ kmod_info.o -lkmod
 */
#include <mach/mach_types.h>

asm(".destructors_used = 0");
asm(".private_extern .destructors_used");

// Functions defined in libkern/c++/OSRuntime.cpp
extern kern_return_t OSRuntimeFinalizeCPP(kmod_info_t *ki, void *data);

// This global symbols will be defined by CreateInfo script's info.c file.
extern kmod_stop_func_t *_antimain;

__private_extern__ kern_return_t _stop(kmod_info_t *ki, void *data)
{
    kern_return_t res = OSRuntimeFinalizeCPP(ki, data);

    if (!res && _antimain)
        res = (*_antimain)(ki, data);

    return res;
}
