/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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
#include <i386/asm.h>

/*
**      ml_get_timebase()
**
**      Entry   - %esp contains pointer to 64 bit structure.
**
**      Exit    - 64 bit structure filled in.
**
*/
ENTRY(ml_get_timebase)

        movl    S_ARG0, %ecx

        rdtsc

        movl    %edx, 0(%ecx)
        movl    %eax, 4(%ecx)

        ret


/* PCI config cycle probing
 *
 *      boolean_t ml_probe_read(vm_offset_t paddr, unsigned int *val)
 *
 *      Read the memory location at physical address paddr.
 *  This is a part of a device probe, so there is a good chance we will
 *  have a machine check here. So we have to be able to handle that.
 *  We assume that machine checks are enabled both in MSR and HIDs
 */
ENTRY(ml_probe_read)

        movl S_ARG0, %ecx
        movl S_ARG1, %eax
        movl 0(%ecx), %ecx
        movl %ecx, 0(%eax)
        movl $1, %eax

        ret


/* PCI config cycle probing - 64-bit
 *
 *      boolean_t ml_probe_read_64(addr64_t paddr, unsigned int *val)
 *
 *      Read the memory location at physical address paddr.
 *  This is a part of a device probe, so there is a good chance we will
 *  have a machine check here. So we have to be able to handle that.
 *  We assume that machine checks are enabled both in MSR and HIDs
 */
ENTRY(ml_probe_read_64)

        /* Only use lower 32 bits of address for now */
        movl S_ARG0, %ecx
        movl S_ARG2, %eax
        movl 0(%ecx), %ecx
        movl %ecx, 0(%eax)
        movl $1, %eax

        ret


/* Read physical address byte
 *
 *      unsigned int ml_phys_read_byte(vm_offset_t paddr)
 *      unsigned int ml_phys_read_byte_64(addr64_t paddr)
 *
 *      Read the byte at physical address paddr. Memory should not be cache inhibited.
 */
ENTRY(ml_phys_read_byte_64)

        /* Only use lower 32 bits of address for now */
        movl S_ARG0, %ecx
        xor %eax, %eax
        movb 0(%ecx), %eax

	ret

ENTRY(ml_phys_read_byte)

        movl S_ARG0, %ecx
        xor %eax, %eax
        movb 0(%ecx), %eax

	ret


/* Read physical address half word
 *
 *      unsigned int ml_phys_read_half(vm_offset_t paddr)
 *      unsigned int ml_phys_read_half_64(addr64_t paddr)
 *
 *      Read the half word at physical address paddr. Memory should not be cache inhibited.
 */
ENTRY(ml_phys_read_half_64)

        /* Only use lower 32 bits of address for now */
        movl S_ARG0, %ecx
        xor %eax, %eax
        movw 0(%ecx), %eax

	ret

ENTRY(ml_phys_read_half)

        movl S_ARG0, %ecx
        xor %eax, %eax
        movw 0(%ecx), %eax

	ret


/* Read physical address word
 *
 *      unsigned int ml_phys_read(vm_offset_t paddr)
 *      unsigned int ml_phys_read_64(addr64_t paddr)
 *      unsigned int ml_phys_read_word(vm_offset_t paddr)
 *      unsigned int ml_phys_read_word_64(addr64_t paddr)
 *
 *      Read the word at physical address paddr. Memory should not be cache inhibited.
 */
ENTRY(ml_phys_read_64)
ENTRY(ml_phys_read_word_64)

        /* Only use lower 32 bits of address for now */
        movl S_ARG0, %ecx
        movl 0(%ecx), %eax

	ret

ENTRY(ml_phys_read)
ENTRY(ml_phys_read_word)

        movl S_ARG0, %ecx
        movl 0(%ecx), %eax

	ret


/* Read physical address double
 *
 *      unsigned long long ml_phys_read_double(vm_offset_t paddr)
 *      unsigned long long ml_phys_read_double_64(addr64_t paddr)
 *
 *      Read the double word at physical address paddr. Memory should not be cache inhibited.
 */
ENTRY(ml_phys_read_double_64)

        /* Only use lower 32 bits of address for now */
        movl S_ARG0, %ecx
        movl 0(%ecx), %eax
        movl 4(%ecx), %edx

	ret

ENTRY(ml_phys_read_double)

        movl S_ARG0, %ecx
        movl 0(%ecx), %eax
        movl 4(%ecx), %edx

	ret


/* Write physical address byte
 *
 *      void ml_phys_write_byte(vm_offset_t paddr, unsigned int data)
 *      void ml_phys_write_byte_64(addr64_t paddr, unsigned int data)
 *
 *      Write the byte at physical address paddr. Memory should not be cache inhibited.
 */
ENTRY(ml_phys_write_byte_64)

        /* Only use lower 32 bits of address for now */
        movl S_ARG0, %ecx
        movl S_ARG2, %eax
        movb %eax, 0(%ecx)

	ret

ENTRY(ml_phys_write_byte)

        movl S_ARG0, %ecx
        movl S_ARG1, %eax
        movb %eax, 0(%ecx)

	ret


/* Write physical address half word
 *
 *      void ml_phys_write_half(vm_offset_t paddr, unsigned int data)
 *      void ml_phys_write_half_64(addr64_t paddr, unsigned int data)
 *
 *      Write the byte at physical address paddr. Memory should not be cache inhibited.
 */
ENTRY(ml_phys_write_half_64)

        /* Only use lower 32 bits of address for now */
        movl S_ARG0, %ecx
        movl S_ARG2, %eax
        movw %eax, 0(%ecx)

	ret

ENTRY(ml_phys_write_half)

        movl S_ARG0, %ecx
        movl S_ARG1, %eax
        movw %eax, 0(%ecx)

	ret


/* Write physical address word
 *
 *      void ml_phys_write(vm_offset_t paddr, unsigned int data)
 *      void ml_phys_write_64(addr64_t paddr, unsigned int data)
 *      void ml_phys_write_word(vm_offset_t paddr, unsigned int data)
 *      void ml_phys_write_word_64(addr64_t paddr, unsigned int data)
 *
 *      Write the word at physical address paddr. Memory should not be cache inhibited.
 */
ENTRY(ml_phys_write_64)
ENTRY(ml_phys_write_word_64)

        /* Only use lower 32 bits of address for now */
        movl S_ARG0, %ecx
        movl S_ARG2, %eax
        movl %eax, 0(%ecx)

	ret

ENTRY(ml_phys_write)
ENTRY(ml_phys_write_word)

        movl S_ARG0, %ecx
        movl S_ARG1, %eax
        movl %eax, 0(%ecx)

	ret


/* Write physical address double word
 *
 *      void ml_phys_write_double(vm_offset_t paddr, unsigned long long data)
 *      void ml_phys_write_double_64(addr64_t paddr, unsigned long long data)
 *
 *      Write the double word at physical address paddr. Memory should not be cache inhibited.
 */
ENTRY(ml_phys_write_double_64)

        /* Only use lower 32 bits of address for now */
        movl S_ARG0, %ecx
        movl S_ARG2, %eax
        movl %eax, 0(%ecx)
        movl S_ARG3, %eax
        movl %eax, 4(%ecx)

	ret

ENTRY(ml_phys_write_double)

        movl S_ARG0, %ecx
        movl S_ARG1, %eax
        movl %eax, 0(%ecx)
        movl S_ARG2, %eax
        movl %eax, 4(%ecx)

	ret
