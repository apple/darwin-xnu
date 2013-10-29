/*
 * Test program for checking the per-thread current working directories
 * are happy.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/param.h>

#ifndef SYS___pthread_chdir
#define SYS___pthread_chdir	348
#endif

#ifndef SYS___pthread_fchdir
#define SYS___pthread_fchdir	349
#endif

/*
 * /tmp is a symlink, so use full path for strict compare
 */
#define WORKDIR		"/private/tmp/ptwork"
#define	WORKDIR1	WORKDIR "/one"
#define	WORKDIR2	WORKDIR "/two"


int
pthread_chdir_np(char *path)
{
	return syscall(SYS___pthread_chdir, path);
}

int
pthread_fchdir_np(int fd)
{
	return syscall(SYS___pthread_fchdir, fd);
}


/*
 * This is a slow routine, just like getcwd(); people should remember that
 * they set something, instead of asking us what they told us.
 */
char *
pthread_getcwd_np(char *buf, size_t size)
{
	int fd_cwd;

	/*
	 * XXX disable compatibility hack, since we have no compatibility
	 * XXX to protect.
	 */
	if (buf == NULL)
		return (NULL);

	/*
	 * Open the "current working directory"; if we are running on a per
	 * thread working directory, that's the one we will get.
	 */
	if ((fd_cwd = open(".", O_RDONLY)) == -1)
		return (NULL);

	/*
	 * Switch off the per thread current working directory, in case we
	 * were on one; this fails if we aren't running with one.
	 */
	if (pthread_fchdir_np( -1) == -1) {
		/* We aren't runniing with one... alll done. */
		close (fd_cwd);
		return (NULL);
	}

	/*
	 * If we successfully switched off, then we switch back...
	 * this may fail catastrophically, if we no longer have rights;
	 * this should never happen, but threads may clobber our fd out
	 * from under us, etc..
	 */
	if (pthread_fchdir_np(fd_cwd) == -1) {
		close(fd_cwd);
		errno = EBADF;	/* sigil for catastrophic failure */
		return (NULL);
	}

	/* Close our directory handle */
	close(fd_cwd);

	/*
	 * And call the regular getcwd(), which will return the per thread
	 * current working directory instead of the process one.
	 */
	return getcwd(buf, size);
}


int
main(int ac, char *av[])
{
	char buf[MAXPATHLEN];
	char *p;

	/*
	 * First, verify that we are NOT using a per thread current working
	 * directory...
	 */
	if (pthread_fchdir_np( -1) != -1) {
		fprintf(stderr, "FAIL: Started out on PT CWD\n");
		exit(1);
	}

	/* Blow the umask to avoid shooting our foot */
	umask(0);		/* "always successful" */

	/* Now set us up the test directories... */

	if (mkdir(WORKDIR, 0777) == -1 && errno != EEXIST) {
		perror("FAIL: mkdir: " WORKDIR);
		exit(2);
	}

	printf("workdir \"" WORKDIR "\" created\n");

	if (mkdir(WORKDIR1, 0777) == -1 && errno != EEXIST) {
		perror("FAIL: mkdir: " WORKDIR1);
		exit(2);
	}

	printf("workdir \"" WORKDIR1 "\" created\n");

	if (mkdir(WORKDIR2, 0777) == -1 && errno != EEXIST) {
		perror("FAIL: mkdir: " WORKDIR2);
		exit(2);
	}

	printf("workdir \"" WORKDIR2 "\" created\n");

	/* Change the process current working directory to WORKDIR1 */

	if (chdir(WORKDIR1) == -1) {
		perror("FAIL: chdir: \"" WORKDIR1 "\" failed\n");
		exit(3);
	}

	printf("process current working directory changed to \"" WORKDIR1 "\"...\n");

	printf("verifying; getcwd says: \"%s\"\n", getcwd(buf, MAXPATHLEN)); 
	if (strcmp(WORKDIR1, buf)) {
		fprintf(stderr, "FAIL: \"%s\" != \"%s\"\n", WORKDIR1, buf);
		exit(3);
	}
	printf("verified.\n");

	/* Verify that we don't get an answer for pthread_getcwd_np() */

	if ((p = pthread_getcwd_np(buf, MAXPATHLEN)) != NULL) {
		fprintf(stderr, "FAIL: pthread_getcwd_np should fail, got \"%s\" instead\n", p);
		exit(4);
	}

	printf("Good so far: pthread_getcwd_np() got no answer (correct)\n");

	if (pthread_chdir_np(WORKDIR2) == -1) {
		perror("FAIL: pthread_chdir_np: " WORKDIR2);
		exit(5);
	}

	printf("Set per thread current working directory to \"" WORKDIR2"\"\n");
	printf("verifying; getcwd says: \"%s\"\n", getcwd(buf, MAXPATHLEN)); 
	if (strcmp(WORKDIR2, buf)) {
		fprintf(stderr, "FAIL: \"%s\" != \"%s\"\n", WORKDIR2, buf);
		exit(3);
	}
	printf("verified.\n");

	/* Now verify we get an answer for pthread_getcwd_np() */
	if ((p = pthread_getcwd_np(buf, MAXPATHLEN)) == NULL) {
		perror("FAIL: pthread_getcwd_np");
		exit(6);
	}

	printf("verifying... pthread_getcwd_np says \"%s\"\n", p);
	if (strcmp(WORKDIR2, buf)) {
		fprintf(stderr, "FAIL: \"%s\" != \"%s\"\n", WORKDIR2, buf);
		exit(7);
	}
	printf("verified.\n");

	printf("verifying our old cwd still exists by going of PT CWD...\n");
	if (pthread_fchdir_np(-1) != 0) {
		perror("FAIL: pthread_fchdir_np");
		exit(8);
	}
	printf("off... but are we really off?\n");

	printf("Check by verifying that pthread_getcwd_np now fails\n");
	if ((p = pthread_getcwd_np(buf, MAXPATHLEN)) != NULL) {
		fprintf(stderr, "FAIL: pthread_getcwd_np should fail, got \"%s\" instead\n", p);
		exit(9);
	}

	printf("verified.\n");

	printf("One last check: see that getcwd says \"" WORKDIR1 "\" again\n");
	printf("verifying; getcwd says: \"%s\"\n", getcwd(buf, MAXPATHLEN)); 
	if (strcmp(WORKDIR1, buf)) {
		fprintf(stderr, "FAIL: \"%s\" != \"%s\"\n", WORKDIR1, buf);
		exit(10);
	}
	printf("verified.\n");


	printf("\nPASS: testing was successful\n");

	exit(0);
}
