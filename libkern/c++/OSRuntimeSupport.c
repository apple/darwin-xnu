// These functions have been moved inline but we need to continue
// exporting the mangled functions for loadable drivers compiled on older
// systems.
// Note that I have had to manually mangle the symbols names.
#if __GNUC__ >= 3
    void _ZN11OSMetaClassdlEPvm(void *mem, unsigned long size) { }
#endif

