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
/*
 * @OSF_FREE_COPYRIGHT@
 */

#include <pexpert/pexpert.h>
#include <kern/debug.h>

static int DEBUGFlag;

void pe_init_debug(void)
{
  if (!PE_parse_boot_arg("debug", &DEBUGFlag))
    DEBUGFlag = 0;
}

void PE_enter_debugger(char *cause)
{
  if (DEBUGFlag & DB_NMI)
    Debugger(cause);
}

/* extern references */
extern void cnputc(char c);
extern void vcattach(void);

/* Globals */
void (*PE_putc)(char c) = 0;

void PE_init_printf(boolean_t vm_initialized)
{
  if (!vm_initialized) {
    PE_putc = cnputc;
  } else {
    vcattach();
  }
}
