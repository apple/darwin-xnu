//
//  PITest.h
//  PerfIndex
//
//  Created by Mark Hamilton on 8/21/13.
//
//

#import <Foundation/Foundation.h>
#import "PerfIndex.h"

@interface PITest : NSObject <HGTest>
{
    int (*setup_func)(int, long long, int, void**);
    int (*execute_func)(int, int, long long, int, void**);
    void (*cleanup_func)(int, long long);

    long long length;
    int numThreads;
    int readyThreadCount;
    int testArgc;
    void** testArgv;
    pthread_mutex_t readyThreadCountLock;
    pthread_cond_t threadsReadyCvar;
    pthread_cond_t startCvar;
    pthread_t* threads;
}

@property NSString* testName;

- (BOOL)setup;
- (BOOL)execute;
- (void)cleanup;


@end