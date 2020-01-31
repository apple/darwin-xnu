#ifndef XNU_QUICK_TEST_HELPERS_H
#define XNU_QUICK_TEST_HELPERS_H

#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syslimits.h>

#define TEST_DIRECTORY "/tmp"

extern char g_target_path[PATH_MAX];

int create_random_name( char *the_pathp, int do_open );
void create_target_directory( const char * the_targetp );
void remove_target_directory( void );

#endif
