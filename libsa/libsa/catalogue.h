bool recordStartupExtensions(void);
bool addExtensionsFromArchive(OSData * mkext);
void removeStartupExtension(const char * extensionName);

OSDictionary * getStartupExtensions(void);
