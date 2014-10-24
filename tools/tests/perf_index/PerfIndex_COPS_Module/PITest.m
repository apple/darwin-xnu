//
//  PITest.m
//  PerfIndex
//
//  Created by Mark Hamilton on 8/21/13.
//
//

#import "PITest.h"
#include <dlfcn.h>
#include <pthread.h>

@implementation PITest

+ (id)testWithOptions:(NSDictionary *)options
{
    PITest *instance = nil;
    if(instance == nil)
        instance = [[PITest alloc] init];
    [instance setTestName:[options objectForKey:@"name"]];
    return instance;
}

- (BOOL)loadPITestAtPath:(NSString*) path
{
    void* handle;
    void* f;

    handle = dlopen([path UTF8String], RTLD_NOW | RTLD_LOCAL);
    if(!handle) {
        return NO;
    }


    f = dlsym(handle, "setup");
    self->setup_func = (int (*)(int, long long, int, void **))f;

    f = dlsym(handle, "execute");
    self->execute_func = (int (*)(int, int, long long, int, void **))f;
    if(!self->execute_func)
        return NO;

    f = dlsym(handle, "cleanup");
    self->cleanup_func = (void (*)(int, long long))f;
    return YES;
}

- (long long)lengthForTest:(NSString*) testName
{
    NSNumber* number;
    long long myLength;
    NSDictionary* lengths = [NSDictionary dictionaryWithObjectsAndKeys:
        @"cpu", [NSNumber numberWithLongLong:2000],
        @"syscall", [NSNumber numberWithLongLong:2500],
        @"memory", [NSNumber numberWithLongLong:1000000],
        @"fault", [NSNumber numberWithLongLong:500],
        @"zfod", [NSNumber numberWithLongLong:500],
        @"file_create", [NSNumber numberWithLongLong:10],
        @"file_read", [NSNumber numberWithLongLong:1000000],
        @"file_write", [NSNumber numberWithLongLong:1000000],
    nil];

    number = (NSNumber*)[lengths objectForKey:testName];
    if(!number) {
        myLength = 10;
    } else {
        myLength = [number longLongValue];
    }

    return myLength;
}

- (BOOL)setup
{
    BOOL success = NO;
    int retval;

    NSString* testPath = [NSString stringWithFormat:@"/AppleInternal/CoreOS/perf_index/%@.dylib", [self testName]];
    success = [self loadPITestAtPath:testPath];
    if(!success) {
        NSLog(@"Failed to load test %@", [self testName]);
        return NO;
    }

    self->length = [self lengthForTest:[self testName]];
    self->numThreads = 1;
    self->testArgc = 0;
    self->testArgv = NULL;

    pthread_cond_init(&self->threadsReadyCvar, NULL);
    pthread_cond_init(&self->startCvar, NULL);
    pthread_mutex_init(&self->readyThreadCountLock, NULL);
    self->readyThreadCount = 0;

    if(self->setup_func) {
        retval = self->setup_func(1, self->length, 0, NULL);
        if(retval != 0) {
            NSLog(@"setup_func failed");
            return NO;
        }
    }

    self->threads = (pthread_t*)malloc(sizeof(pthread_t)*self->numThreads);

    for(int thread_index = 0; thread_index < self->numThreads; thread_index++) {
        NSNumber* my_thread_index = [NSNumber numberWithInt:thread_index];
        NSArray *arg = [NSArray arrayWithObjects:my_thread_index, self, nil];
        retval = pthread_create(&threads[thread_index], NULL, thread_setup, (__bridge void*)arg);
        if(retval != 0) {
            NSLog(@"pthread_create failed");
            free(self->threads);
            return NO;
        }
    }

    pthread_mutex_lock(&self->readyThreadCountLock);
    if(self->readyThreadCount != self->numThreads) {
        pthread_cond_wait(&self->threadsReadyCvar, &self->readyThreadCountLock);
    }
    pthread_mutex_unlock(&self->readyThreadCountLock);
    return YES;
}

- (BOOL)execute
{
    pthread_cond_broadcast(&self->startCvar);
    for(int thread_index = 0; thread_index < self->numThreads; thread_index++) {
        pthread_join(self->threads[thread_index], NULL);
    }
    return YES;
}

- (void)cleanup
{
    free(self->threads);
    if(self->cleanup_func)
        self->cleanup_func(0, self->length);
}

void* thread_setup(void* arg)
{
    int my_index = (int)[(NSNumber*)[(__bridge NSArray*)arg objectAtIndex:0] integerValue];
    PITest* test = (PITest*)[(__bridge NSArray*)arg objectAtIndex:1];

    long long work_size = test->length / test->numThreads;
    int work_remainder = test->length % test->numThreads;

    if(work_remainder > my_index) {
        work_size++;
    }

    pthread_mutex_lock(&test->readyThreadCountLock);
    test->readyThreadCount++;

    if(test->readyThreadCount == test->numThreads)
        pthread_cond_signal(&test->threadsReadyCvar);
    pthread_cond_wait(&test->startCvar, &test->readyThreadCountLock);
    pthread_mutex_unlock(&test->readyThreadCountLock);
    test->execute_func(my_index, test->numThreads, work_size, test->testArgc, test->testArgv);

    return NULL;
}

@end
