// These functions have been moved inline but we need to continue
// exporting the mangled functions for loadable drivers compiled on older
// systems.
// Note that I have had to manually mangle the symbols names.
void _ZN11OSMetaClassdlEPvm(void *mem, unsigned long size);
void *_ZN11OSMetaClassnwEm(unsigned long size);

void
_ZN11OSMetaClassdlEPvm(__attribute__((unused)) void *mem, __attribute__((__unused__)) unsigned long size)
{
}
void *
_ZN11OSMetaClassnwEm(__attribute__((unused)) unsigned long size)
{
	return (void *)0ULL;
}
