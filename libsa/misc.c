/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
#include <libsa/mach/mach.h>
#include <sys/systm.h>
#include <stdarg.h>
#include <vm/vm_kern.h>
#include <libsa/stdlib.h>


__private_extern__
char *kld_basefile_name = "(memory-resident kernel)";


/* from osfmk/kern/printf.c */
extern void _doprnt(
        register const char     *fmt,
        va_list                 *argp,
        void                    (*putc)(char),
        int                     radix);

/* from osfmk/kern/printf.c */
extern void conslog_putc(char c);

__private_extern__
void kld_error_vprintf(const char *format, va_list ap) {
    _doprnt(format, &ap, &conslog_putc, 10);
    return;
}
