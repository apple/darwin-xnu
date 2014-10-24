#ifndef __RAMDISK_H_
#define __RAMDISK_H_

int setup_ram_volume(const char* name, char* path);
int cleanup_ram_volume(char* path);

#endif
