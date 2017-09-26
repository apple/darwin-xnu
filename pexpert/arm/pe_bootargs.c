/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
 */
#include <pexpert/pexpert.h>
#include <pexpert/boot.h>

char *
PE_boot_args(
	void)
{
	return (char *)((boot_args *)PE_state.bootArgs)->CommandLine;
}
