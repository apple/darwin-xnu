#include <stdio.h>
/*
Sample test file. Do not remove this.
*/
int main(int argc, char *argv[]){
	char os_version[20] = TARGET_OS_VERS;
	char os_build[20] = TARGET_OS_BUILD_VERS;
	printf("Sample test for xnu unit tests. This file is just an example for future unit tests.\n");
	printf("This test was build with OS version %s and build %s\n", os_version, os_build); 
	/* an example of how SDKTARGET is used for different builds */
#ifdef TARGET_SDK_macosx
	printf("The SDKTARGET for building this test is macosx\n");
#endif

#ifdef TARGET_SDK_macosx_internal
	printf("The SDKTARGET for building this test is macosx.internal\n");
#endif

#ifdef TARGET_SDK_iphoneos
	printf("The SDKTARGET for building this test is iphoneos\n");
#endif

#ifdef TARGET_SDK_iphoneos_internal
	printf("The SDKTARGET for building this test is iphoneos.internal\n");
#endif

	return 0;
}
