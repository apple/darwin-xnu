//
//  pgokext.c
//  pgokext
//
//  Created by Lawrence D'Anna on 12/15/16.
//
//

#include <mach/mach_types.h>

kern_return_t pgokext_start(kmod_info_t * ki, void *d);
kern_return_t pgokext_stop(kmod_info_t *ki, void *d);

kern_return_t
pgokext_start(kmod_info_t * ki, void *d)
{
	return KERN_SUCCESS;
}

kern_return_t
pgokext_stop(kmod_info_t *ki, void *d)
{
	return KERN_SUCCESS;
}
