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
#include <pexpert/protos.h>
#include <pexpert/boot.h>

typedef struct {
    char *        name;
    unsigned long length;
    void *        value;
} prop_init;

typedef struct {
    long   zero;
    long   nProps;
    long   nChildren;
} node_init;

typedef struct {
    long   one;
    long * length;
    long * address;
} data_init;

typedef union {
    prop_init propInit;
    node_init nodeInit;
    data_init dataInit;
} dt_init;

typedef struct {
    long   length;
    long * address;
} dt_data;

extern boot_args fakePPCBootArgs;
extern unsigned char *nptr;

void   printdt(void);
void * createdt(dt_init * template, long * retSize);

#define NODE(props,children)  \
        {{(char *)0, props, (void *)children }}

#define INTPROP(name,value)   \
        {{name, 4, (void *)value }}

#define PROP(name,value)      \
        {{name, sizeof( value), value }}

#define NULLPROP(name)        \
        {{name, 0, (void *)0 }}

#define DATAPROP(data)    \
		{{(char *)1, (long)&((data).length), (void *)&((data).address) }}
        
#define DATANODE(data)    \
		{{(char *)1, (long)&((data).length), (void *)&((data).address) }}
