extern bool recordStartupExtensions(void);
extern bool addExtensionsFromArchive(OSData * mkext);
extern void removeStartupExtension(const char * extensionName);

extern OSDictionary * getStartupExtensions(void);

extern void clearStartupExtensionsAndLoaderInfo(void);

extern bool uncompressModule(OSData *compressed, /* out */ OSData ** file);
