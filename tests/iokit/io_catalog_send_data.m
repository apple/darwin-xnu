/*
 * io_catalog_send_data.m
 *
 * A regression test to build an IORegistry entry with mismatching
 * IOService and IOUserClientClass via IOCatalogueSendData, to verify
 * if exploit risk still exists in IOCatalogueSendData.
 *
 */
#include <darwintest.h>

#include <Foundation/Foundation.h>
#include <IOKit/IOCFSerialize.h>
#include <IOKit/IOKitLib.h>

#define kIOClassKey		@"IOClass"
#define kIOProviderClassKey	@"IOProviderClass"
#define kIOMatchCategoryKey	@"IOMatchCategory"
#define kIOUserClientClassKey	@"IOUserClientClass"
#define vIOProviderClassValue	@"IOResources"

T_GLOBAL_META(T_META_NAMESPACE("xnu.iokit"),
	T_META_RUN_CONCURRENTLY(true));

kern_return_t
build_ioregistry_by_catalog_send_data(const char *match_name,
    const char *userclient_name, const char *service_name)
{
	kern_return_t kret;

	NSArray *rootCatalogueArray = @[@{
	    kIOProviderClassKey: vIOProviderClassValue,
	    kIOClassKey: @(service_name),
	    kIOUserClientClassKey: @(userclient_name),
	    kIOMatchCategoryKey: @(match_name)
	}];

	CFDataRef cfData = IOCFSerialize((__bridge CFTypeRef)rootCatalogueArray,
	    kIOCFSerializeToBinary);

	kret = IOCatalogueSendData(MACH_PORT_NULL, 1, CFDataGetBytePtr(cfData),
	    CFDataGetLength(cfData));

	if (cfData) {
		CFRelease(cfData);
	}

	return kret;
}

bool
test_open_ioregistry(const char *match_name, const char *service_name,
    bool exploit)
{
	kern_return_t kret;
	bool ioreg_found = false;
	CFStringRef cfstrMatchName = NULL;
	io_connect_t conn = IO_OBJECT_NULL;
	io_iterator_t iter = IO_OBJECT_NULL, obj = IO_OBJECT_NULL;
	CFMutableDictionaryRef service_info = NULL, properties = NULL;

	service_info = IOServiceMatching(service_name);
	kret = IOServiceGetMatchingServices(kIOMasterPortDefault, service_info, &iter);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kret, "IOServiceGetMatchingServices");
	cfstrMatchName = CFStringCreateWithCString(kCFAllocatorDefault,
	    match_name, kCFStringEncodingUTF8);

	while (obj = IOIteratorNext(iter)) {
		kret = IORegistryEntryCreateCFProperties(obj, &properties,
		    kCFAllocatorDefault, kNilOptions);
		if (kret != KERN_SUCCESS) {
			T_LOG("IORegistryEntryCreateCFProperties fails, 0x%08X",
			    (uint32_t)kret);
			IOObjectRelease(obj);
			continue;
		}

		CFStringRef value = CFDictionaryGetValue(properties, CFSTR("IOMatchCategory"));
		if (value && CFGetTypeID(value) == CFStringGetTypeID() &&
		    CFEqual(value, cfstrMatchName)) {
			ioreg_found = true;
		} else {
			IOObjectRelease(obj);
			continue;
		}

		if (!exploit) {
			goto bail;
		}

		T_LOG("try to exploit by opening io service, possibly panic?");
		IOServiceOpen(obj, mach_task_self(), 0, &conn);
		IOObjectRelease(obj);

		break;
	}

bail:
	if (cfstrMatchName) {
		CFRelease(cfstrMatchName);
	}

	if (properties) {
		CFRelease(properties);
	}

	if (iter != IO_OBJECT_NULL) {
		IOObjectRelease(iter);
	}

	if (conn != IO_OBJECT_NULL) {
		IOServiceClose(conn);
	}

	return ioreg_found;
}

T_DECL(io_catalog_send_data_test, "regression test to build an IORegistry entry"
    " with mismatching IOService and IOUserClientClass by IOCatalogueSendData, "
    "to verify if exploit risk still exists in IOCatalogueSendData for "
    "potential DoS - <rdar://problem/31558871>")
{
	kern_return_t kret;

	kret = build_ioregistry_by_catalog_send_data("fooBar",
	    "IOSurfaceRootUserClient", "IOReportHub");
#if (TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR)
	/* this trick to build an entry by io_catalog_send_data should fail */
	T_EXPECT_EQ(kret, kIOReturnNotPrivileged, "build an entry with"
	    " mismatch IOService and IOUserClientClass by IOCatalogueSendData "
	    "should fail as kIOReturnNotPrivileged");
#else
	T_EXPECT_EQ(kret, KERN_SUCCESS, "IOCatalogueSendData should return success with kextd");
#endif
	T_EXPECT_FALSE(test_open_ioregistry("fooBar", "IOReportHub", false),
	    "Mismatched entry built by IOCatalogueSendData should not be opened");
}
