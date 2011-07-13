#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <err.h>
#include <pthread.h>

extern char **environ;

char * const *newargv;

void usage(void);

void *work(void *);

int main(int argc, char *argv[]) {

    int i, count, threadcount;
    int ret;
    pthread_t *threads;

    if (argc < 4) {
        usage();
    }

    threadcount = atoi(argv[1]);
    count = atoi(argv[2]);
    
    newargv = &argv[3];

    threads = (pthread_t *)calloc(threadcount, sizeof(pthread_t));
    for (i=0; i < threadcount; i++) {
        ret = pthread_create(&threads[i], NULL, work, (void *)(intptr_t)count);
        if (ret) {
            err(1, "pthread_create");
        }
    }
    
    for (i=0; i < threadcount; i++) {
        ret = pthread_join(threads[i], NULL);
        if (ret) {
            err(1, "pthread_join");
        }
    }
    
    return 0;
}

void usage(void) {
    fprintf(stderr, "Usage: %s <threadcount> <count> <program> [<arg1> [<arg2> ...]]\n",
            getprogname());
    exit(1);
}

void *work(void *arg)
{
    int count = (int)(intptr_t)arg;
    int i;
    int ret;
    pid_t pid;

    for (i=0; i < count; i++) {
        ret = posix_spawn(&pid, newargv[0], NULL, NULL, newargv, environ);
        if (ret != 0) {
            errc(1, ret, "posix_spawn(%s)", newargv[0]);
        }
        
        while (-1 == waitpid(pid, &ret, 0)) {
            if (errno != EINTR) {
                err(1, "waitpid(%d)", pid);
            }
        }
        
        if (WIFSIGNALED(ret)) {
            errx(1, "process exited with signal %d", WTERMSIG(ret));
        } else if (WIFSTOPPED(ret)) {
            errx(1, "process stopped with signal %d", WSTOPSIG(ret));
        } else if (WIFEXITED(ret)) {
            if (WEXITSTATUS(ret) != 42) {
                errx(1, "process exited with unexpected exit code %d", WEXITSTATUS(ret));
            }
        } else {
            errx(1, "unknown exit condition %x", ret);
        }
    }

    return NULL;
}
