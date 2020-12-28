/*
 * Copyright (c) 2019 Apple Computer, Inc. All rights reserved.
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

enum ptrauth_key {
  ptrauth_key_asia = 0,
  ptrauth_key_asib = 1,
  ptrauth_key_asda = 2,
  ptrauth_key_asdb = 3,

  /* A process-independent key which can be used to sign code pointers.
     Signing and authenticating with this key is a no-op in processes
     which disable ABI pointer authentication. */
  ptrauth_key_process_independent_code = ptrauth_key_asia,

  /* A process-specific key which can be used to sign code pointers.
     Signing and authenticating with this key is enforced even in processes
     which disable ABI pointer authentication. */
  ptrauth_key_process_dependent_code = ptrauth_key_asib,

  /* A process-independent key which can be used to sign data pointers.
     Signing and authenticating with this key is a no-op in processes
     which disable ABI pointer authentication. */
  ptrauth_key_process_independent_data = ptrauth_key_asda,

  /* A process-specific key which can be used to sign data pointers.
     Signing and authenticating with this key is a no-op in processes
     which disable ABI pointer authentication. */
  ptrauth_key_process_dependent_data = ptrauth_key_asdb,

  /* The key used to sign C function pointers.
     The extra data is always 0. */
  ptrauth_key_function_pointer = ptrauth_key_process_independent_code,

  /* The key used to sign return addresses on the stack.
     The extra data is based on the storage address of the return address.
     On ARM64, that is always the storage address of the return address plus 8
     (or, in other words, the value of the stack pointer on function entry) */
  ptrauth_key_return_address = ptrauth_key_process_dependent_code,

  /* The key used to sign frame pointers on the stack.
     The extra data is based on the storage address of the frame pointer.
     On ARM64, that is always the storage address of the frame pointer plus 16
     (or, in other words, the value of the stack pointer on function entry) */
  ptrauth_key_frame_pointer = ptrauth_key_process_dependent_data,

  /* The key used to sign block function pointers, including:
       invocation functions,
       block object copy functions,
       block object destroy functions,
       __block variable copy functions, and
       __block variable destroy functions.
     The extra data is always the address at which the function pointer
     is stored.

     Note that block object pointers themselves (i.e. the direct
     representations of values of block-pointer type) are not signed. */
  ptrauth_key_block_function = ptrauth_key_asia,

  /* The key used to sign C++ v-table pointers.
     The extra data is always 0. */
  ptrauth_key_cxx_vtable_pointer = ptrauth_key_asda

};

