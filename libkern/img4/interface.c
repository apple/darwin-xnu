#include <libkern/libkern.h>
#include <libkern/section_keywords.h>
#include <libkern/img4/interface.h>

#if defined(SECURITY_READ_ONLY_LATE)
SECURITY_READ_ONLY_LATE(const img4_interface_t *) img4if = NULL;
#else
const img4_interface_t *img4if = NULL;
#endif

void
img4_interface_register(const img4_interface_t *i4)
{
	if (img4if) {
		panic("img4 interface already set");
	}
	img4if = i4;
}
