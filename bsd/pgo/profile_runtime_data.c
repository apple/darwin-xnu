#include <mach/vm_param.h>

/*
 * This tells compiler_rt not to include userspace-specific stuff writing
 * profile data to a file.
 */
int __llvm_profile_runtime = 0;

/* compiler-rt requires this.  It uses it to page-align
 * certain things inside its buffers.
 */

extern int getpagesize(void);

int
getpagesize()
{
	return PAGE_SIZE;
}
