/*
 * Copyright (c) 2003-2007 Apple Inc. All rights reserved.
 */
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>

#include <machine/machine_routines.h>

extern uint64_t	wake_abstime;

static
SYSCTL_QUAD(_machdep, OID_AUTO, wake_abstime,
            CTLFLAG_RD, &wake_abstime,
            "Absolute Time at the last wakeup");

static int
sysctl_time_since_reset SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2, oidp)
	int error = 0;
	uint64_t return_value = 0;

	return_value = ml_get_time_since_reset();

	SYSCTL_OUT(req, &return_value, sizeof(return_value));

	return error;
}

SYSCTL_PROC(_machdep, OID_AUTO, time_since_reset,
            CTLFLAG_RD | CTLTYPE_QUAD | CTLFLAG_LOCKED,
            0, 0, sysctl_time_since_reset, "I",
            "Continuous time since last SOC boot/wake started");

static int
sysctl_wake_conttime SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2, oidp)
	int error = 0;
	uint64_t return_value = 0;

	return_value = ml_get_conttime_wake_time();

	SYSCTL_OUT(req, &return_value, sizeof(return_value));

	return error;
}

SYSCTL_PROC(_machdep, OID_AUTO, wake_conttime,
            CTLFLAG_RD | CTLTYPE_QUAD | CTLFLAG_LOCKED,
            0, 0, sysctl_wake_conttime, "I",
            "Continuous Time at the last wakeup");


