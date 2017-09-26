#include <darwintest.h>

#include "xnu_quick_test_helpers.h"

#include <fcntl.h>
#include <unistd.h>

void create_target_directory( const char * the_targetp )
{
    int             err;
    const char *    my_targetp;

    my_targetp = getenv("TMPDIR");
    if ( my_targetp == NULL )
        my_targetp = "/tmp";

    T_ASSERT_LT( strlen( the_targetp ), (unsigned long)( PATH_MAX - 1 ),
        "check target path too long - \"%s\"", the_targetp );

    for ( ;; ) {
        int         my_rand;
        char        my_name[64];
        
        my_rand = rand( );
        sprintf( &my_name[0], "xnu_quick_test-%d", my_rand );
        T_ASSERT_LT( strlen( &my_name[0] ) + strlen( the_targetp ) + 2, (unsigned long)PATH_MAX,
            "check target path plus our test directory name is too long: "
            "target path - \"%s\" test directory name - \"%s\"",
            the_targetp, &my_name[0] );

        /* append generated directory name onto our path */
        g_target_path[0] = 0x00;
        strcat( &g_target_path[0], the_targetp );
        if ( g_target_path[ (strlen(the_targetp) - 1) ] != '/' ) {
            strcat( &g_target_path[0], "/" );
        }
        strcat( &g_target_path[0], &my_name[0] );
        
        /* try to create the test directory */
        err = mkdir( &g_target_path[0], (S_IRWXU | S_IRWXG | S_IROTH) );
        if ( err == 0 ) {
            break;
        }
        err = errno;
        if ( EEXIST != err ) {
            T_ASSERT_FAIL( "test directory creation failed - \"%s\" \n"
                "mkdir call failed with error %d - \"%s\"", 
                &g_target_path[0], errno, strerror( err) );
        }
    }

} /* create_target_directory */

/*
 * create_random_name - creates a file with a random / unique name in the given directory.
 * when do_open is true we create a file else we generaate a name that does not exist in the
 * given directory (we do not create anything when do_open is 0).
 * WARNING - caller provides enough space in path buffer for longest possible name.
 * WARNING - assumes caller has appended a trailing '/' on the path passed to us.
 * RAND_MAX is currently 2147483647 (ten characters plus one for a slash)
 */
int create_random_name( char *the_pathp, int do_open ) {
    int     i, my_err;
    int     my_fd = -1;
    
    for ( i = 0; i < 1; i++ ) {
        int         my_rand;
        char        *myp;
        char        my_name[32];
        
        my_rand = rand( );
        sprintf( &my_name[0], "%d", my_rand );
        T_ASSERT_LT_ULONG((strlen( &my_name[0] ) + strlen( the_pathp ) + 2), (unsigned long)PATH_MAX,
            "check if path to test file is less than PATH_MAX");

        // append generated file name onto our path
        myp = strrchr( the_pathp, '/' );
        *(myp + 1) = 0x00;
        strcat( the_pathp, &my_name[0] );
        if ( do_open ) {
            /* create a file with this name */
            my_fd = open( the_pathp, (O_RDWR | O_CREAT | O_EXCL),
                            (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) );
            T_EXPECT_TRUE((my_fd != -1 || errno == EEXIST), "open file with name %s", the_pathp);
            
            if( errno == EEXIST )
                continue;
        }
        else {
            /* make sure the name is unique */
            struct stat     my_sb;
            my_err = stat( the_pathp, &my_sb );
            T_EXPECT_TRUE((my_err == 0 || errno == ENOENT), "make sure the name is unique");
            
            if(errno == ENOENT) break;
            /* name already exists, try another */
            i--;
            continue;
        }
    }
    
    if ( my_fd != -1 )
        close( my_fd );

    if(do_open && my_fd == -1)
        return 1;

    return 0;
} /* create_random_name */

void remove_target_directory() {
    rmdir(&g_target_path[0]);
}

