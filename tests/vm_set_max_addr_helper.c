#include <mach/mach_init.h>
#include <mach/mach_vm.h>
#include <stdlib.h>

int
main(void)
{
	kern_return_t kr;
	mach_vm_address_t addr = 50ULL * 1024ULL * 1024ULL * 1024ULL;

	kr = mach_vm_allocate(current_task(), &addr, 4096, VM_FLAGS_FIXED);

	if (kr == KERN_SUCCESS) {
		return 0;
	} else {
		return 1;
	}
}
