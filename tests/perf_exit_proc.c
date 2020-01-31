#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <mach/mach.h>
#include <mach/mach_vm.h>

static void*
loop(__attribute__ ((unused)) void *arg)
{
	while (1) {
	}
}


static int
run_additional_threads(int nthreads)
{
	for (int i = 0; i < nthreads; i++) {
		pthread_t pthread;
		int err;

		err = pthread_create(&pthread, NULL, loop, NULL);
		if (err) {
			return err;
		}
	}

	return 0;
}

static int
allocate_and_wire_memory(mach_vm_size_t size)
{
	int err;
	task_t task = mach_task_self();
	mach_vm_address_t addr;

	if (size <= 0) {
		return 0;
	}

	err = mach_vm_allocate(task, &addr, size, VM_FLAGS_ANYWHERE);
	if (err != KERN_SUCCESS) {
		printf("mach_vm_allocate returned non-zero: %s\n", mach_error_string(err));
		return err;
	}
	err = mach_vm_protect(task, addr, size, 0, VM_PROT_READ | VM_PROT_WRITE);;
	if (err != KERN_SUCCESS) {
		printf("mach_vm_protect returned non-zero: %s\n", mach_error_string(err));
		return err;
	}
	host_t host_priv_port;
	err = host_get_host_priv_port(mach_host_self(), &host_priv_port);
	if (err != KERN_SUCCESS) {
		printf("host_get_host_priv_port retruned non-zero: %s\n", mach_error_string(err));
		return err;
	}
	err = mach_vm_wire(host_priv_port, task, addr, size, VM_PROT_READ | VM_PROT_WRITE);
	if (err != KERN_SUCCESS) {
		printf("mach_vm_wire returned non-zero: %s\n", mach_error_string(err));
		return err;
	}

	return 0;
}

int
main(int argc, char *argv[])
{
	int nthreads = 0;
	int err;
	mach_vm_size_t wired_mem = 0;

	if (argc > 1) {
		nthreads = (int)strtoul(argv[1], NULL, 10);
	}
	if (argc > 2) {
		wired_mem = (mach_vm_size_t)strtoul(argv[2], NULL, 10);
	}

	err = allocate_and_wire_memory(wired_mem);
	if (err) {
		return err;
	}

	err = run_additional_threads(nthreads);
	if (err) {
		return err;
	}

	return 0;
}
