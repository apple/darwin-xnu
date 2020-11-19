#include <darwintest.h>
#include <mach/mach.h>
#include <IOKit/IOKitLib.h>
#include <Kernel/IOKit/crypto/AppleKeyStoreDefs.h>


T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));

T_DECL(ioconnectasyncmethod_referenceCnt,
    "Test IOConnectCallAsyncMethod with referenceCnt < 1",
    T_META_ASROOT(true))
{
	io_service_t service;
	io_connect_t conn;
	mach_port_t wakePort;
	uint64_t reference = 0;
	service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching(kAppleKeyStoreServiceName));
	if (service == IO_OBJECT_NULL) {
		T_SKIP("Service " kAppleKeyStoreServiceName " could not be opened. skipping test");
	}
	T_ASSERT_NE(service, MACH_PORT_NULL, "got " kAppleKeyStoreServiceName " service");
	T_ASSERT_MACH_SUCCESS(IOServiceOpen(service, mach_task_self(), 0, &conn), "opened connection to service");
	T_ASSERT_MACH_SUCCESS(mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &wakePort), "allocated wake port");
	T_ASSERT_MACH_ERROR(IOConnectCallAsyncMethod(conn, 0 /* selector */, wakePort, &reference, 0 /* referenceCnt */,
	    NULL /* input */, 0 /* inputCnt */, NULL /* inputStruct */, 0 /* inputStructCnt */,
	    NULL /* output */, 0 /* outputCnt */, NULL /* outputStruct */, 0 /* outputStructCntP */), kIOReturnBadArgument, "IOConnectCallAsyncMethod should fail with kIOReturnBadArgument");
	IOServiceClose(conn);
	mach_port_mod_refs(mach_task_self(), wakePort, MACH_PORT_RIGHT_RECEIVE, -1);
}
