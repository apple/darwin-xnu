#include <spawn.h>
/*
 * Returns the subcpu type for the architecture for which the
 * binary was compiled.
 */
int
main(void)
{
#if defined(__x86_64__)
	return CPU_SUBTYPE_X86_64_ALL;
#elif defined(__arm64__) && defined(__LP64__)
	return CPU_SUBTYPE_ARM64_ALL;
#elif defined(__arm64__)
	return CPU_SUBTYPE_ARM64_32_ALL;
#elif defined(__arm__)
	return CPU_SUBTYPE_ARM_V7K;
#else
#error unknown architecture
#endif
}
