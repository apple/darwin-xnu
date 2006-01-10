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

#include <pexpert/protos.h>

#include "fakePPCStructs.h"

boot_args fakePPCBootArgs = { .Version = kBootArgsVersion };

void * createdt(dt_init * template, long * retSize)
{
    dt_init *    next;
    size_t       size, allocSize;
    vm_address_t out, saveout;
    void *       source;
    
    // calc size of expanded data
    for ( next = template, allocSize = 0;
          next;
          next++ )
    {
        if ( next->nodeInit.zero == 0 )
        {
            if( next->nodeInit.nProps == 0) break;
            allocSize += 2 * sizeof( long);
        }
        else if ( next->dataInit.one == 1 )
        {
            allocSize += *(next->dataInit.length);
        }
        else if ( next->stringInit.two == 2 )
        {
            dt_data *dp = (dt_data *)(next->stringInit.data);
            allocSize += (32 + 4 + 3 + dp->length) & (-4);
        }
        else
        {
            allocSize += (32 + 4 + 3 + next->propInit.length) & (-4);
        }
    }
    saveout = out = (vm_address_t) kalloc(allocSize);
    if ( out == 0 ) return 0;

    // copy out
    for ( next = template; next; next++)
    {
        if ( next->nodeInit.zero == 0 )
        {
            if ( next->nodeInit.nProps == 0 ) break;
            source = &next->nodeInit.nProps;
            size = 2 * sizeof( long);
        }
        else if ( next->dataInit.one == 1 )
        {
            *((long *)next->dataInit.address) = out;
            source = 0;
            size   = *(next->dataInit.length);
        }
        else if ( next->stringInit.two == 2 )
        {
            dt_data *dp = (dt_data *)next->stringInit.data;
            bcopy( (void *)(uintptr_t)next->stringInit.name, (void *)out, 32);
            out += 32;
            size = dp->length;
            *(long *)out = size;
            out += sizeof(long);
            source = (char *)dp->address;
            size = (size + 3) & (-4);
        }
        else
        {
            bcopy( (void *)(uintptr_t)next->propInit.name, (void *)out, 32);
            out += 32;
            size = next->propInit.length;
            *(long *)out = size;
            out += sizeof(long);
            if ( size == 4 )
                source = &next->propInit.value;
            else {
                source = next->propInit.value;
                size = (size + 3) & (-4);
            }
        }
        if ( source )
            bcopy(source, (void *)out, size);
        else
            bzero((void *)out, size);
        out += size;
    }

    if( allocSize != (out - saveout))
        printf("WARNING: DT corrupt (%x)\n", (out - saveout) - allocSize);

    *retSize = allocSize;
    return( (void *)saveout );
}

unsigned char *nptr;

#define kPropNameLength 32

typedef struct property_t {
    char                name[kPropNameLength];  // NUL terminated property name
    unsigned long       length;         // Length (bytes) of folloing prop value
    unsigned long       *value;         // Variable length value of property
} property_t;

typedef struct node_t {
    unsigned long       nProperties;    // Number of props[] elements (0 => end)
    unsigned long       nChildren;      // Number of children[] elements
    property_t *props;      // array size == nProperties
    struct node_t   *children;     // array size == nChildren
} node_t;


unsigned int indent = 0;

void printdt()
{
    node_t *nodeptr = (node_t *)nptr;
    unsigned long num_props    = nodeptr->nProperties;
    unsigned long len;
    unsigned int i, j;
    unsigned char *sptr;

    nptr = (unsigned char *)&nodeptr->props;
    for (i=0; i < num_props; i++)
    {
        for (j = 0; j < indent; j++)
            printf("    ");
        printf("'");
        printf("%s", nptr);
        nptr+=32;
        len = *((unsigned long*)nptr);
        nptr += 4;
        printf("'\t\t(%ld)  '", len);
        sptr = nptr;
        for (j = 0; j < len; j++)
            printf("%2.2x", *nptr++);
        printf("'\t('%s')\n", sptr);
        if (len % 4)
            nptr += (4 - (len % 4));
    }
    for (i=0; i<nodeptr->nChildren; i++)
    {
        indent++;
        printdt();
        indent--;
    }
}

