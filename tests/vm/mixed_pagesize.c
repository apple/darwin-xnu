#include <mach/vm_page_size.h>
#include <stdio.h>

int
main(int argc __unused, char **argv __unused)
{
	/*
	 * This test should have been launched with the 4K pagesize flag.
	 * Verify that the page size globals were set.
	 */
	if (vm_page_shift != 12) {
		fprintf(stderr, "Expected: vm_page_shift == 12. Actual: vm_page_shift == %d\n", vm_page_shift);
		return 1;
	}
	if (vm_page_size != 4096) {
		fprintf(stderr, "Expected: vm_page_size == 4096. Actual: vm_page_shift == %zu\n", vm_page_size);
		return 1;
	}
	if (vm_page_mask != 4095) {
		fprintf(stderr, "Expected: vm_page_mask == 4095. Actual: vm_page_mask == %zu\n", vm_page_mask);
		return 1;
	}
	return 0;
}
