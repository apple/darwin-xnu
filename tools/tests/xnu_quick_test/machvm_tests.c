/*
 *  machvm_tests.c
 *  xnu_quick_test
 *
 *  Copyright 2008 Apple Inc. All rights reserved.
 *
 */

#include "tests.h"
#include <mach/mach.h>
#include <unistd.h>
#include <err.h>
#include <sys/param.h>
#include <mach-o/ldsyms.h>

extern int		g_is_under_rosetta;

int machvm_tests( void * the_argp )
{
	int pagesize = getpagesize();
	int regionsizes[] = { 1, 3, 7, 13, 77, 1223 }; /* sizes must be in increasing order */
	char *regionbuffers[] = { NULL, NULL, NULL, NULL, NULL, NULL };
	int i;
	kern_return_t kret;
	
	/* Use vm_allocate to grab some memory */
	for (i=0; i < sizeof(regionsizes)/sizeof(regionsizes[0]); i++) {
		vm_address_t addr = 0;

		kret = vm_allocate(mach_task_self(), &addr, regionsizes[i]*pagesize, VM_FLAGS_ANYWHERE);
		if (kret != KERN_SUCCESS) {
			warnx("vm_allocate of %d pages failed: %d", regionsizes[i], kret);
			goto fail;
		}
		regionbuffers[i] = (char *)addr;
	}
	
	/* deallocate one range without having touched it, scribble on another, then deallocate that one */
	kret = vm_deallocate(mach_task_self(), (vm_address_t)regionbuffers[4], regionsizes[4]*pagesize);
	if (kret != KERN_SUCCESS) {
		warnx("vm_deallocate of %d pages failed: %d", regionsizes[4], kret);
		goto fail;
	}
	regionbuffers[4] = NULL;
	
	memset(regionbuffers[3], 0x4f, pagesize*MIN(3, regionsizes[3]));
	
	kret = vm_deallocate(mach_task_self(), (vm_address_t)regionbuffers[3], regionsizes[3]*pagesize);
	if (kret != KERN_SUCCESS) {
		warnx("vm_deallocate of %d pages failed: %d", regionsizes[3], kret);
		goto fail;
	}
	regionbuffers[3] = NULL;
	
	// populate the largest buffer with a byte pattern that matches the page offset, then fix it to readonly
	for (i=0; i < regionsizes[5]; i++) {
		memset(regionbuffers[5] + i*pagesize, (unsigned char)i, pagesize);		
	}
	kret = vm_protect(mach_task_self(), (vm_offset_t)regionbuffers[5], regionsizes[5]*pagesize, FALSE, VM_PROT_READ);
	if (kret != KERN_SUCCESS) {
		warnx("vm_protect of %d pages failed: %d", regionsizes[5], kret);
		goto fail;
	}
	
	// read the last few pagse of the largest buffer and verify its contents
	{
		vm_offset_t	newdata;
		mach_msg_type_number_t newcount;
		
		kret = vm_read(mach_task_self(), (vm_address_t)regionbuffers[5] + (regionsizes[5]-5)*pagesize, 5*pagesize,
					   &newdata, &newcount);
		if (kret != KERN_SUCCESS) {
			warnx("vm_read of %d pages failed: %d", 5, kret);
			goto fail;
		}
		
		if (0 != memcmp((char *)newdata, regionbuffers[5] + (regionsizes[5]-5)*pagesize,
						5*pagesize)) {
			warnx("vm_read comparison of %d pages failed", 5);
			kret = -1;
			vm_deallocate(mach_task_self(), newdata, 5*pagesize);
			goto fail;
		}

		kret = vm_deallocate(mach_task_self(), newdata, 5*pagesize);
		if (kret != KERN_SUCCESS) {
			warnx("vm_deallocate of %d pages failed: %d", 5, kret);
			goto fail;
		}
	}
	
	// do a list read to repopulate slots 3 and 4
	{
		vm_read_entry_t	readlist;
		
		readlist[0].address = (vm_offset_t)regionbuffers[5] + 10*pagesize;
		readlist[0].size = regionsizes[3]*pagesize;
		readlist[1].address = (vm_offset_t)regionbuffers[5] + 10*pagesize + regionsizes[3]*pagesize;
		readlist[1].size = regionsizes[4]*pagesize;
		
		kret = vm_read_list(mach_task_self(), readlist, 2);
		if (kret != KERN_SUCCESS) {
			warnx("vm_read_list failed: %d", kret);
			goto fail;
		}
		
		if (0 != memcmp((char *)readlist[0].address, regionbuffers[5] + 10*pagesize,
						regionsizes[3]*pagesize)) {
			warnx("vm_read_list comparison of allocation 0 failed");
			kret = -1;
			vm_deallocate(mach_task_self(), readlist[0].address, readlist[0].size);
			vm_deallocate(mach_task_self(), readlist[1].address, readlist[1].size);
			goto fail;
		}

		if (0 != memcmp((char *)readlist[1].address, regionbuffers[5] + 10*pagesize + regionsizes[3]*pagesize,
						regionsizes[4]*pagesize)) {
			warnx("vm_read_list comparison of allocation 1 failed");
			kret = -1;
			vm_deallocate(mach_task_self(), readlist[0].address, readlist[0].size);
			vm_deallocate(mach_task_self(), readlist[1].address, readlist[1].size);
			goto fail;
		}
		
		regionbuffers[3] = (char *)readlist[0].address;
		regionbuffers[4] = (char *)readlist[1].address;
	}
	
	// do a read_overwrite and copy, which should be about the same
	{
		vm_size_t count;
		
		kret = vm_read_overwrite(mach_task_self(), (vm_offset_t)regionbuffers[3],
								 regionsizes[0]*pagesize,
								 (vm_offset_t)regionbuffers[0],
								 &count);
		if (kret != KERN_SUCCESS) {
			warnx("vm_read_overwrite of %d pages failed: %d", regionsizes[0], kret);
			goto fail;
		}
		
		kret = vm_copy(mach_task_self(), (vm_offset_t)regionbuffers[0],
								 regionsizes[0]*pagesize,
								 (vm_offset_t)regionbuffers[1]);
		if (kret != KERN_SUCCESS) {
			warnx("vm_copy of %d pages failed: %d", regionsizes[0], kret);
			goto fail;
		}
		
		if (0 != memcmp(regionbuffers[1], regionbuffers[3],
						regionsizes[0]*pagesize)) {
			warnx("vm_read_overwrite/vm_copy comparison failed");
			kret = -1;
			goto fail;
		}
	}		
	
	// do a vm_copy of our mach-o header and compare. Rosetta doesn't support this, though
	if (!g_is_under_rosetta) {

		kret = vm_write(mach_task_self(), (vm_address_t)regionbuffers[2],
						(vm_offset_t)&_mh_execute_header, pagesize);
		if (kret != KERN_SUCCESS) {
			warnx("vm_write of %d pages failed: %d", 1, kret);
			goto fail;
		}
		
		if (_mh_execute_header.magic != *(uint32_t *)regionbuffers[2]) {
			warnx("vm_write comparison failed");
			kret = -1;
			goto fail;
		}	
	}
	
	// check that the vm_protects above worked
	{
		vm_address_t addr = (vm_address_t)regionbuffers[5]+7*pagesize;
		vm_size_t size = pagesize;
		int _basic[VM_REGION_BASIC_INFO_COUNT];
		vm_region_basic_info_t basic = (vm_region_basic_info_t)_basic;
		int _basic64[VM_REGION_BASIC_INFO_COUNT_64];
		vm_region_basic_info_64_t basic64 = (vm_region_basic_info_64_t)_basic64;
		mach_msg_type_number_t	infocnt;
		mach_port_t	objname;
		
#if !__LP64__
		infocnt = VM_REGION_BASIC_INFO_COUNT;
		kret = vm_region(mach_task_self(), &addr, &size, VM_REGION_BASIC_INFO,
						 (vm_region_info_t)basic, &infocnt, &objname);
		if (kret != KERN_SUCCESS) {
			warnx("vm_region(VM_REGION_BASIC_INFO) failed: %d", kret);
			goto fail;
		}
		if (VM_REGION_BASIC_INFO_COUNT != infocnt) {
			warnx("vm_region(VM_REGION_BASIC_INFO) returned a bad info count");
			kret = -1;
			goto fail;
		}

		// when we did the vm_read_list above, it should have split this region into
		// a 10 page sub-region
		if (addr != (vm_address_t)regionbuffers[5] || size != 10*pagesize) {
			warnx("vm_region(VM_REGION_BASIC_INFO) returned a bad region range");
			kret = -1;
			goto fail;
		}

		if (basic->protection != VM_PROT_READ) {
			warnx("vm_region(VM_REGION_BASIC_INFO) returned a bad protection");
			kret = -1;
			goto fail;
		}
#endif
		
		infocnt = VM_REGION_BASIC_INFO_COUNT_64;
		// intentionally use VM_REGION_BASIC_INFO and get up-converted
		kret = vm_region_64(mach_task_self(), &addr, &size, VM_REGION_BASIC_INFO,
						 (vm_region_info_t)basic64, &infocnt, &objname);
		if (kret != KERN_SUCCESS) {
			warnx("vm_region_64(VM_REGION_BASIC_INFO) failed: %d", kret);
			goto fail;
		}
		if (VM_REGION_BASIC_INFO_COUNT_64 != infocnt) {
			warnx("vm_region_64(VM_REGION_BASIC_INFO) returned a bad info count");
			kret = -1;
			goto fail;
		}
		
		// when we did the vm_read_list above, it should have split this region into
		// a 10 page sub-region
		if (addr != (vm_address_t)regionbuffers[5] || size != 10*pagesize) {
			warnx("vm_region_64(VM_REGION_BASIC_INFO) returned a bad region range");
			kret = -1;
			goto fail;
		}
		
		if (basic64->protection != VM_PROT_READ) {
			warnx("vm_region_64(VM_REGION_BASIC_INFO) returned a bad protection");
			kret = -1;
			goto fail;
		}
		
#if !__LP64__
		// try to compare some stuff. Particularly important for fields after offset
		if (!g_is_under_rosetta) {
			if (basic->offset != basic64->offset ||
				basic->behavior != basic64->behavior ||
				basic->user_wired_count != basic64->user_wired_count) {
				warnx("vm_region and vm_region_64 did not agree");
				kret = -1;
				goto fail;			
			}
		}		
#endif
	}
	
fail:
	for (i=0; i < sizeof(regionsizes)/sizeof(regionsizes[0]); i++) {
		if (regionbuffers[i]) {
			vm_deallocate(mach_task_self(), (vm_address_t)regionbuffers[i], regionsizes[i]*pagesize);
		}
	}
	
	return kret;
}

