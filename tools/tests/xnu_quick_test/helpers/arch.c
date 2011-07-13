#include <spawn.h>
#include <mach/machine.h>

/*
 * Helper function for posix_spawn test: returns binary type as exit code.
 */
int main()
{
#if __i386__
	return CPU_TYPE_I386;
#endif /* __i386__ */
#if __x86_64__
	return CPU_TYPE_X86_64;
#endif /* __x86_64__ */
	/* unrecognized type */
	return -1;
}
