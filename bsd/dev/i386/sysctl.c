/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
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

#include <string.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <i386/cpuid.h>

static int
hw_cpu_sysctl SYSCTL_HANDLER_ARGS
{
    __unused struct sysctl_oid *unused_oidp = oidp;
    i386_cpu_info_t *cpu_info = cpuid_info();
    void *ptr = (uint8_t *)cpu_info + (uint32_t)arg1;
    int value;

    if (arg2 == -1) {
        ptr = *(char **)ptr;
        arg2 = 0;
    }

    if (arg2 == 0 && ((char *)ptr)[0] == '\0') {
        return ENOENT;
    }

    if (arg2 == sizeof(uint8_t)) {
	value = (uint32_t) *(uint8_t *)ptr;
	ptr = &value;
	arg2 = sizeof(uint32_t);
    }
    return SYSCTL_OUT(req, ptr, arg2 ? (size_t) arg2 : strlen((char *)ptr)+1);
}

static int
hw_cpu_features SYSCTL_HANDLER_ARGS
{
    __unused struct sysctl_oid *unused_oidp = oidp;
    __unused void *unused_arg1 = arg1;
    __unused int unused_arg2 = arg2; 
    char buf[256];

    buf[0] = '\0';
    cpuid_get_feature_names(cpuid_features(), buf, sizeof(buf));

    return SYSCTL_OUT(req, buf, strlen(buf) + 1);
}

SYSCTL_NODE(_machdep, OID_AUTO, cpu, CTLFLAG_RW, 0,
	"CPU info");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, vendor, CTLTYPE_STRING | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_vendor), 0,
	    hw_cpu_sysctl, "A", "CPU vendor");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, brand_string, CTLTYPE_STRING | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_brand_string), 0,
	    hw_cpu_sysctl, "A", "CPU brand string");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, model_string, CTLTYPE_STRING | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_model_string), -1,
	    hw_cpu_sysctl, "A", "CPU model string");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, value, CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_value), sizeof(uint32_t),
	    hw_cpu_sysctl, "I", "CPU value");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, family, CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_family), sizeof(uint8_t),
	    hw_cpu_sysctl, "I", "CPU family");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, model, CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_model), sizeof(uint8_t),
	    hw_cpu_sysctl, "I", "CPU model");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, extmodel, CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_extmodel), sizeof(uint8_t),
	    hw_cpu_sysctl, "I", "CPU extended model");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, extfamily, CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_extfamily), sizeof(uint8_t),
	    hw_cpu_sysctl, "I", "CPU extended family");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, stepping, CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_stepping), sizeof(uint8_t),
	    hw_cpu_sysctl, "I", "CPU stepping");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, feature_bits, CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_features), sizeof(uint32_t),
	    hw_cpu_sysctl, "I", "CPU features");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, signature, CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_signature), sizeof(uint32_t),
	    hw_cpu_sysctl, "I", "CPU signature");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, brand, CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_brand), sizeof(uint8_t),
	    hw_cpu_sysctl, "I", "CPU brand");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, features, CTLTYPE_STRING | CTLFLAG_RD, 
	    0, 0,
	    hw_cpu_features, "A", "CPU feature names");


struct sysctl_oid *machdep_sysctl_list[] =
{
    &sysctl__machdep_cpu,
    &sysctl__machdep_cpu_vendor,
    &sysctl__machdep_cpu_brand_string,
    &sysctl__machdep_cpu_model_string,
    &sysctl__machdep_cpu_value,
    &sysctl__machdep_cpu_family,
    &sysctl__machdep_cpu_model,
    &sysctl__machdep_cpu_extmodel,
    &sysctl__machdep_cpu_extfamily,
    &sysctl__machdep_cpu_feature_bits,
    &sysctl__machdep_cpu_stepping,
    &sysctl__machdep_cpu_signature,
    &sysctl__machdep_cpu_brand,
    &sysctl__machdep_cpu_features,
    (struct sysctl_oid *) 0
};

