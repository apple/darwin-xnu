#include <libkern/libkern.h>
#include <libkern/section_keywords.h>
#include <libkern/coretrust/coretrust.h>

#if defined(SECURITY_READ_ONLY_LATE)
SECURITY_READ_ONLY_LATE(const coretrust_t *) coretrust = NULL;
#else
const coretrust_t *coretrust = NULL;
#endif

void
coretrust_interface_register(const coretrust_t *ct)
{
	if (coretrust) {
		panic("coretrust interface already set");
	}
	coretrust = ct;
}
