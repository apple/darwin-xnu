/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
#include <pexpert/protos.h>
#include <pexpert/boot.h>

typedef struct {
    const char *  name;
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

typedef struct {
    long         two;
    const char * name;
    void *       data;
} string_init;

typedef union {
    prop_init propInit;
    node_init nodeInit;
    data_init dataInit;
    string_init stringInit;
} dt_init;

typedef struct {
    long   length;
    void * address;
} dt_data;

extern boot_args fakePPCBootArgs;
extern unsigned char *nptr;

void   printdt(void);
void * createdt(dt_init * template, long * retSize);

#define NODE(props,children)  \
        { .nodeInit = {0, props, children }}

#define INTPROP(name,value)   \
        { .propInit = {name, 4, (void *)(uintptr_t)value }}

#define PROP(name,value)      \
        { .propInit = {name, sizeof( value), (void *)(uintptr_t)value }}

#define STRINGPROP(name,value) \
        { .stringInit = { 2, name, (void *)&(value) }}

#define NULLPROP(name)        \
        { propInit = {name, 0, (void *)0 }}

#define DATAPROP(data)    \
	{ .dataInit = {1, &((data).length), (long *) &((data).address) }}
        
#define DATANODE(data)    \
	{ .dataInit = {1, &((data).length), (long *)&((data).address) }}
