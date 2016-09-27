//
//  Tests.swift
//
//  Some of these tests here verify that kdd is able to parse old
//  kcdata files and generate the correct output. To do so, we include
//  compressed versions of the raw kcdata and as well as the expected
//  plist output.
//
//  NOTE: If you're adding sample data/plist files, you'll need to first
//        add them to the project and then make sure each is part of the
//        tests target.
//
//  Other tests verify the expected behavior of libkdd for certain
//  situations.
//
//

import XCTest
import Foundation

// Swift's bridging to uuid_t is awkward.

func nsuuid2uuid_t(nsuuid : NSUUID) -> uuid_t {
    let dat = nsuuid2array(nsuuid)
    return nsarray2uuid(dat)
}

func nsarray2uuid(x : AnyObject) -> uuid_t {
    let a = x as! NSArray
    return uuid_t(UInt8(a[0] as! Int),
                  UInt8(a[1] as! Int),
                  UInt8(a[2] as! Int),
                  UInt8(a[3] as! Int),
                  UInt8(a[4] as! Int),
                  UInt8(a[5] as! Int),
                  UInt8(a[6] as! Int),
                  UInt8(a[7] as! Int),
                  UInt8(a[8] as! Int),
                  UInt8(a[9] as! Int),
                  UInt8(a[10] as! Int),
                  UInt8(a[11] as! Int),
                  UInt8(a[12] as! Int),
                  UInt8(a[13] as! Int),
                  UInt8(a[14] as! Int),
                  UInt8(a[15] as! Int))
}

func nsuuid2array(uuid : NSUUID) -> [Int] {
    var ret = [Int]()
    let ptr = UnsafeMutablePointer<UInt8>.alloc(16)
    
    defer { ptr.dealloc(16) }

    uuid.getUUIDBytes(ptr)
    for i in 0..<16 {
        ret.append(Int(ptr[i]))
    }
    return ret
}

func decompress(data:NSData) throws -> NSData {
    var stream = z_stream(next_in: nil, avail_in: 0, total_in: 0, next_out: nil, avail_out: 0, total_out: 0, msg: nil, state: nil, zalloc: nil, zfree: nil, opaque: nil, data_type: 0, adler: 0, reserved: 0)

    let bufsize : Int = 1000
    let buffer = UnsafeMutablePointer<UInt8>.alloc(bufsize)
    defer { buffer.dealloc(bufsize) }
    let output = NSMutableData()
    stream.next_out = buffer
    stream.avail_out = UInt32(bufsize)
    stream.next_in = UnsafeMutablePointer(data.bytes)
    stream.avail_in = UInt32(data.length)
    inflateInit2_(&stream, 16+MAX_WBITS, ZLIB_VERSION, Int32(sizeof(z_stream)))

    while (true) {
        let z = inflate(&stream, Z_NO_FLUSH);
        if (z == Z_OK || z == Z_STREAM_END) {
            output.appendBytes(buffer, length: bufsize - Int(stream.avail_out))
            stream.avail_out = UInt32(bufsize)
            stream.next_out = buffer
            if (z == Z_STREAM_END) {
                return output;
            }
        } else {
            throw NSError(domain: "zlib", code: Int(z), userInfo: nil)
        }
    }
}



class Tests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        continueAfterFailure = false
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func parseBuffer(buffer:NSData) throws -> NSDictionary {
        var error : NSError?
        guard let dict = parseKCDataBuffer(UnsafeMutablePointer(buffer.bytes), UInt32(buffer.length), &error)
        else {
                XCTAssert(error != nil)
                throw error!
        }
        return dict
    }

    func testPaddingFlags(pad : Int) {
        let buffer = NSMutableData(capacity:1000)!

        var item = kcdata_item()

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        item.type = UInt32(KCDATA_TYPE_LIBRARY_LOADINFO)
        item.flags = UInt64(pad)
        item.size = UInt32(sizeof(dyld_uuid_info_32))
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        let uuid = NSUUID(UUIDString: "de305d54-75b4-431b-adb2-eb6b9e546014")!

        var payload = dyld_uuid_info_32(imageLoadAddress: 42, imageUUID: nsuuid2uuid_t(uuid))
        buffer.appendBytes(&payload, length:sizeof(dyld_uuid_info_32))

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        guard let dict = try? self.parseBuffer(buffer)
            else { XCTFail(); return; }

        var uuidarray = nsuuid2array(uuid)
        for _ in 0..<pad {
            uuidarray.removeLast()
        }

        XCTAssert(dict["kcdata_crashinfo"]?["dyld_load_info"]??["imageLoadAddress"] == 42)
        XCTAssert(dict["kcdata_crashinfo"]?["dyld_load_info"]??["imageUUID"] == uuidarray)
    }

    func testPaddingFlags() {
        for i in 0..<15 {
            testPaddingFlags(i)
        }
    }

    func testBootArgs() {
        let s = "hello, I am some boot args"

        let buffer = NSMutableData(capacity:1000)!

        var item = kcdata_item()

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        item.type = UInt32(STACKSHOT_KCTYPE_BOOTARGS)
        item.flags = 0
        item.size = UInt32(s.utf8.count + 1)
        buffer.appendBytes(&item, length: sizeof(kcdata_item))
        s.nulTerminatedUTF8.withUnsafeBufferPointer({
            buffer.appendBytes($0.baseAddress, length:s.utf8.count + 1)
        })

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        guard let dict = try? self.parseBuffer(buffer) else { XCTFail(); return; }
        XCTAssert(dict["kcdata_crashinfo"]?["boot_args"] == s)
    }

    func testBootArgsMissingNul() {
        let s = "hello, I am some boot args"

        let buffer = NSMutableData(capacity:1000)!

        var item = kcdata_item()

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        item.type = UInt32(STACKSHOT_KCTYPE_BOOTARGS)
        item.flags = 0
        item.size = UInt32(s.utf8.count)
        buffer.appendBytes(&item, length: sizeof(kcdata_item))
        s.nulTerminatedUTF8.withUnsafeBufferPointer({
            buffer.appendBytes($0.baseAddress, length:s.utf8.count)
        })

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        XCTAssert( (try? self.parseBuffer(buffer)) == nil )
    }

    func testLoadInfo() {
        let buffer = NSMutableData(capacity:1000)!

        var item = kcdata_item()

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        item.type = UInt32(KCDATA_TYPE_LIBRARY_LOADINFO)
        item.flags = 0
        item.size = UInt32(sizeof(dyld_uuid_info_32))
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        let uuid = NSUUID(UUIDString: "de305d54-75b4-431b-adb2-eb6b9e546014")!

        var payload = dyld_uuid_info_32(imageLoadAddress: 42, imageUUID: nsuuid2uuid_t(uuid))
        buffer.appendBytes(&payload, length:sizeof(dyld_uuid_info_32))

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        guard let dict = try? self.parseBuffer(buffer)
        else { XCTFail(); return; }

        XCTAssert(dict["kcdata_crashinfo"]?["dyld_load_info"]??["imageLoadAddress"] == 42)
        XCTAssert(dict["kcdata_crashinfo"]?["dyld_load_info"]??["imageUUID"] == nsuuid2array(uuid))
    }

    func testLoadInfoWrongSize() {
        // test what happens when a struct size is short

        let buffer = NSMutableData(capacity:1000)!

        var item = kcdata_item()

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        item.type = UInt32(KCDATA_TYPE_LIBRARY_LOADINFO)
        item.flags = 0
        item.size = UInt32(sizeof(dyld_uuid_info_32)) - 1
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        let uuid = NSUUID(UUIDString: "de305d54-75b4-431b-adb2-eb6b9e546014")!

        var payload = dyld_uuid_info_32(imageLoadAddress: 42, imageUUID: nsuuid2uuid_t(uuid))
        buffer.appendBytes(&payload, length:sizeof(dyld_uuid_info_32) - 1)

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        guard let dict = try? self.parseBuffer(buffer)
        else { XCTFail(); return; }
        XCTAssert(dict["kcdata_crashinfo"]?["dyld_load_info"]??["imageLoadAddress"] == 42)
        var uuidarray = nsuuid2array(uuid)
        uuidarray.removeLast()
        XCTAssert(dict["kcdata_crashinfo"]?["dyld_load_info"]??["imageUUID"] == uuidarray)
    }

    func testLoadInfoWayWrongSize() {
        // test what happens when a struct size is short

        let buffer = NSMutableData(capacity:1000)!

        var item = kcdata_item()

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        item.type = UInt32(KCDATA_TYPE_LIBRARY_LOADINFO)
        item.flags = 0
        item.size = UInt32(sizeof(dyld_uuid_info_32)) - 16
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        let uuid = NSUUID(UUIDString: "de305d54-75b4-431b-adb2-eb6b9e546014")!

        var payload = dyld_uuid_info_32(imageLoadAddress: 42, imageUUID: nsuuid2uuid_t(uuid))
        buffer.appendBytes(&payload, length:sizeof(dyld_uuid_info_32) - 16)

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        guard let dict = try? self.parseBuffer(buffer)
        else { XCTFail(); return; }
        XCTAssert(dict["kcdata_crashinfo"]?["dyld_load_info"]??["imageLoadAddress"] == 42)
        XCTAssert(dict["kcdata_crashinfo"]?["dyld_load_info"]??["imageUUID"] == nil)
    }

    func testLoadInfoPreposterousWrongSize() {
        // test what happens when a struct size is short

        let buffer = NSMutableData(capacity:1000)!

        var item = kcdata_item()

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        item.type = UInt32(KCDATA_TYPE_LIBRARY_LOADINFO)
        item.flags = 0
        item.size = UInt32(1)
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        var payload = UInt8(42)
        buffer.appendBytes(&payload, length:1)

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        guard let dict = try? self.parseBuffer(buffer)
        else { XCTFail(); return; }
        XCTAssert(dict["kcdata_crashinfo"]?["dyld_load_info"]??["imageLoadAddress"] == nil)
        XCTAssert(dict["kcdata_crashinfo"]?["dyld_load_info"]??["imageUUID"] == nil)
    }


    func testNewArray(n : Int, pad : Int) {
        let buffer = NSMutableData(capacity:1000)!
        var item = kcdata_item()

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        item.type = UInt32(KCDATA_TYPE_ARRAY_PAD0) + UInt32(pad)
        item.flags = UInt64(STACKSHOT_KCTYPE_DONATING_PIDS) << 32 | UInt64(n)
        item.size = UInt32(n * sizeof(UInt32) + pad)
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        for i in 0..<n {
            var payload = UInt32(42 * i)
            buffer.appendBytes(&payload, length:sizeof(UInt32))
        }

        for i in 0..<pad {
            var payload = UInt8(42-i)
            buffer.appendBytes(&payload, length:sizeof(UInt8))
        }

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        guard let dict = try? self.parseBuffer(buffer)
        else { XCTFail(); return; }
        XCTAssert(dict["kcdata_crashinfo"]?["donating_pids"]??.count == n)
        for i in 0..<n {
            let x = dict["kcdata_crashinfo"] as? NSDictionary
            let y = x?["donating_pids"] as? NSArray
            XCTAssert((y?[i]) as? NSObject == 42 * i)
        }
    }

    func testNewArrays() {
        self.testNewArray(0,pad:0)
        for i in 1..<20 {
            for pad in 0..<16 {
                self.testNewArray(i, pad:pad)
            }
        }
    }


    func testArrayLoadInfo(n : Int) {
        let buffer = NSMutableData(capacity:1000)!
        var item = kcdata_item()

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        item.type = UInt32(KCDATA_TYPE_ARRAY_PAD0)
        item.flags = UInt64(KCDATA_TYPE_LIBRARY_LOADINFO) << 32 | UInt64(n)
        item.size = UInt32(n * sizeof(dyld_uuid_info_32))
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        let uuid = NSUUID(UUIDString: "de305d54-75b4-431b-adb2-eb6b9e546014")!


        for i in 0..<n {
            var payload = dyld_uuid_info_32(imageLoadAddress:UInt32(i+42), imageUUID: nsuuid2uuid_t(uuid))

            buffer.appendBytes(&payload, length:sizeof(dyld_uuid_info_32))
        }

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        guard let dict = try? self.parseBuffer(buffer)
        else { XCTFail(); return; }
        XCTAssert(dict["kcdata_crashinfo"]?["dyld_load_info"]??.count == n)
        for i in 0..<n {
            XCTAssert(dict["kcdata_crashinfo"]?["dyld_load_info"]??[i]?["imageLoadAddress"] == 42+i)
            XCTAssert(dict["kcdata_crashinfo"]?["dyld_load_info"]??[i]?["imageUUID"] == nsuuid2array(uuid))
        }
    }

    func testArrayLoadInfo() {
        for n in 0..<20 {
            testArrayLoadInfo(n)
        }
    }

    func testArrayLoadInfoWrongSize() {
        // test what happens when array element sizes are too short

        let n = 7
        let wrong = 1
        let buffer = NSMutableData(capacity:1000)!
        var item = kcdata_item()

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        item.type = UInt32(KCDATA_TYPE_ARRAY_PAD0)
        item.flags = UInt64(KCDATA_TYPE_LIBRARY_LOADINFO) << 32 | UInt64(n)
        item.size = UInt32(n * (sizeof(dyld_uuid_info_32) - wrong))
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        let uuid = NSUUID(UUIDString: "de305d54-75b4-431b-adb2-eb6b9e546014")!

        for i in 0..<n {
            var payload = dyld_uuid_info_32(imageLoadAddress:UInt32(i+42), imageUUID: nsuuid2uuid_t(uuid))
            buffer.appendBytes(&payload, length:sizeof(dyld_uuid_info_32)-wrong)
        }

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        var uuidarray = nsuuid2array(uuid)
        uuidarray.removeLast()

        guard let dict = try? self.parseBuffer(buffer)
        else { XCTFail(); return; }
        XCTAssert(dict["kcdata_crashinfo"]?["dyld_load_info"]??.count == n)
        for i in 0..<n {
            XCTAssert(dict["kcdata_crashinfo"]?["dyld_load_info"]??[i]?["imageLoadAddress"] == 42+i)
            XCTAssert(dict["kcdata_crashinfo"]?["dyld_load_info"]??[i]?["imageUUID"] == uuidarray)
        }
    }


    func testArrayLoadInfoWayWrongSize() {
        // test what happens when array element sizes are too short

        let n = 7
        let wrong = 16
        let buffer = NSMutableData(capacity:1000)!
        var item = kcdata_item()

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        item.type = UInt32(KCDATA_TYPE_ARRAY_PAD0)
        item.flags = UInt64(KCDATA_TYPE_LIBRARY_LOADINFO) << 32 | UInt64(n)
        item.size = UInt32(n * (sizeof(dyld_uuid_info_32) - wrong))
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        let uuid = NSUUID(UUIDString: "de305d54-75b4-431b-adb2-eb6b9e546014")!

        for i in 0..<n {
            var payload = dyld_uuid_info_32(imageLoadAddress:UInt32(i+42), imageUUID: nsuuid2uuid_t(uuid))
            buffer.appendBytes(&payload, length:sizeof(dyld_uuid_info_32)-wrong)
        }

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        guard let dict = try? self.parseBuffer(buffer)
        else { XCTFail(); return; }
        XCTAssert(dict["kcdata_crashinfo"]?["dyld_load_info"]??.count == n)
        for i in 0..<n {
            XCTAssert(dict["kcdata_crashinfo"]?["dyld_load_info"]??[i]?["imageLoadAddress"] == 42+i)
            XCTAssert(dict["kcdata_crashinfo"]?["dyld_load_info"]??[i]?["imageUUID"] == nil)
        }
    }

    func testArrayLoadInfoPreposterouslyWrongSize() {
        // test what happens when array element sizes are too short

        let n = 7
        let wrong = 19
        let buffer = NSMutableData(capacity:1000)!
        var item = kcdata_item()

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        item.type = UInt32(KCDATA_TYPE_ARRAY_PAD0)
        item.flags = UInt64(KCDATA_TYPE_LIBRARY_LOADINFO) << 32 | UInt64(n)
        item.size = UInt32(n * (sizeof(dyld_uuid_info_32) - wrong))
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        for i in 0..<n {
            var payload = UInt8(42*i)
            buffer.appendBytes(&payload, length:1)
        }

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        guard let dict = try? self.parseBuffer(buffer)
        else { XCTFail(); return; }
        XCTAssert(dict["kcdata_crashinfo"]?["dyld_load_info"]??.count == n)
        for i in 0..<n {
            XCTAssert(dict["kcdata_crashinfo"]?["dyld_load_info"]??[i]?["imageLoadAddress"] == nil)
            XCTAssert(dict["kcdata_crashinfo"]?["dyld_load_info"]??[i]?["imageUUID"] == nil)
        }
    }


    func testNested() {
        let buffer = NSMutableData(capacity:1000)!

        var item = kcdata_item()

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        item.type = UInt32(TASK_CRASHINFO_CRASHED_THREADID)
        item.flags = 0
        item.size = UInt32(sizeof(UInt64))
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        var payload : UInt64 = 42
        buffer.appendBytes(&payload, length:sizeof(UInt64))

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        let buffer2 = NSMutableData(capacity:1000)!

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer2.appendBytes(&item, length: sizeof(kcdata_item))

        item.type = UInt32(KCDATA_TYPE_NESTED_KCDATA)
        item.flags = 0
        item.size = UInt32(buffer.length)
        buffer2.appendBytes(&item, length: sizeof(kcdata_item))
        buffer2.appendData(buffer)

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer2.appendBytes(&item, length: sizeof(kcdata_item))

        guard let dict2 = try? self.parseBuffer(buffer2)
            else { XCTFail(); return; }

        XCTAssert(dict2["kcdata_crashinfo"]?["kcdata_crashinfo"]??["crashed_threadid"] == 42)
    }


    func testReadThreadid() {
        let buffer = NSMutableData(capacity:1000)!

        var item = kcdata_item()

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        item.type = UInt32(TASK_CRASHINFO_CRASHED_THREADID)
        item.flags = 0
        item.size = UInt32(sizeof(UInt64))
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        var payload : UInt64 = 42
        buffer.appendBytes(&payload, length:sizeof(UInt64))

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        guard let dict = try? self.parseBuffer(buffer)
        else { XCTFail(); return; }

        XCTAssert(dict["kcdata_crashinfo"]!["crashed_threadid"] == 42)
    }
    

    func testRepeatedKey() {
        // test a repeated item of the same key causes error

        let buffer = NSMutableData(capacity:1000)!

        var item = kcdata_item()

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        item.type = UInt32(TASK_CRASHINFO_CRASHED_THREADID)
        item.flags = 0
        item.size = UInt32(sizeof(UInt64))
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        var payload : UInt64 = 42
        buffer.appendBytes(&payload, length:sizeof(UInt64))

        item.type = UInt32(TASK_CRASHINFO_CRASHED_THREADID)
        item.flags = 0
        item.size = UInt32(sizeof(UInt64))
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        payload = 42
        buffer.appendBytes(&payload, length:sizeof(UInt64))

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        XCTAssert( (try? self.parseBuffer(buffer)) == nil )
    }


    func testContainer() {
        let buffer = NSMutableData(capacity:1000)!

        var item = kcdata_item()
        var payload64 : UInt64
        var payload32 : UInt32

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        item.type = UInt32(KCDATA_TYPE_CONTAINER_BEGIN)
        item.flags = 0
        item.size = UInt32(sizeof(UInt32))
        buffer.appendBytes(&item, length: sizeof(kcdata_item))
        payload32 = UInt32(STACKSHOT_KCCONTAINER_TASK)
        buffer.appendBytes(&payload32, length:sizeof(UInt32))

        item.type = UInt32(TASK_CRASHINFO_CRASHED_THREADID)
        item.flags = 0
        item.size = UInt32(sizeof(UInt64))
        buffer.appendBytes(&item, length: sizeof(kcdata_item))
        payload64 = 42
        buffer.appendBytes(&payload64, length:sizeof(UInt64))

        item.type = UInt32(KCDATA_TYPE_CONTAINER_END)
        item.flags = 0
        item.size = UInt32(sizeof(UInt32))
        buffer.appendBytes(&item, length: sizeof(kcdata_item))
        payload32 = UInt32(STACKSHOT_KCCONTAINER_TASK)
        buffer.appendBytes(&payload32, length:sizeof(UInt32))


        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        guard let dict = try? self.parseBuffer(buffer)
        else { XCTFail(); return; }

        XCTAssert(dict["kcdata_crashinfo"]?["task_snapshots"]??["0"]??["crashed_threadid"] == 42)

    }

    func testRepeatedContainer() {
        //repeated container of same name and key shoudl fail

        let buffer = NSMutableData(capacity:1000)!

        var item = kcdata_item()
        var payload64 : UInt64
        var payload32 : UInt32

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        item.type = UInt32(KCDATA_TYPE_CONTAINER_BEGIN)
        item.flags = 0
        item.size = UInt32(sizeof(UInt32))
        buffer.appendBytes(&item, length: sizeof(kcdata_item))
        payload32 = UInt32(STACKSHOT_KCCONTAINER_TASK)
        buffer.appendBytes(&payload32, length:sizeof(UInt32))

        item.type = UInt32(TASK_CRASHINFO_CRASHED_THREADID)
        item.flags = 0
        item.size = UInt32(sizeof(UInt64))
        buffer.appendBytes(&item, length: sizeof(kcdata_item))
        payload64 = 42
        buffer.appendBytes(&payload64, length:sizeof(UInt64))

        item.type = UInt32(KCDATA_TYPE_CONTAINER_END)
        item.flags = 0
        item.size = UInt32(sizeof(UInt32))
        buffer.appendBytes(&item, length: sizeof(kcdata_item))
        payload32 = UInt32(STACKSHOT_KCCONTAINER_TASK)
        buffer.appendBytes(&payload32, length:sizeof(UInt32))


        item.type = UInt32(KCDATA_TYPE_CONTAINER_BEGIN)
        item.flags = 0
        item.size = UInt32(sizeof(UInt32))
        buffer.appendBytes(&item, length: sizeof(kcdata_item))
        payload32 = UInt32(STACKSHOT_KCCONTAINER_TASK)
        buffer.appendBytes(&payload32, length:sizeof(UInt32))

        item.type = UInt32(TASK_CRASHINFO_CRASHED_THREADID)
        item.flags = 0
        item.size = UInt32(sizeof(UInt64))
        buffer.appendBytes(&item, length: sizeof(kcdata_item))
        payload64 = 42
        buffer.appendBytes(&payload64, length:sizeof(UInt64))

        item.type = UInt32(KCDATA_TYPE_CONTAINER_END)
        item.flags = 0
        item.size = UInt32(sizeof(UInt32))
        buffer.appendBytes(&item, length: sizeof(kcdata_item))
        payload32 = UInt32(STACKSHOT_KCCONTAINER_TASK)
        buffer.appendBytes(&payload32, length:sizeof(UInt32))

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        XCTAssert( (try? self.parseBuffer(buffer)) == nil )
    }


    func testContainerNoEnd() {
        let buffer = NSMutableData(capacity:1000)!

        var item = kcdata_item()
        var payload64 : UInt64
        var payload32 : UInt32

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        item.type = UInt32(KCDATA_TYPE_CONTAINER_BEGIN)
        item.flags = 0
        item.size = UInt32(sizeof(UInt32))
        buffer.appendBytes(&item, length: sizeof(kcdata_item))
        payload32 = UInt32(STACKSHOT_KCCONTAINER_TASK)
        buffer.appendBytes(&payload32, length:sizeof(UInt32))

        item.type = UInt32(TASK_CRASHINFO_CRASHED_THREADID)
        item.flags = 0
        item.size = UInt32(sizeof(UInt64))
        buffer.appendBytes(&item, length: sizeof(kcdata_item))
        payload64 = 42
        buffer.appendBytes(&payload64, length:sizeof(UInt64))

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        XCTAssert( (try? self.parseBuffer(buffer)) == nil )
    }

    func testContainerNoEndNoEnd() {
        let buffer = NSMutableData(capacity:1000)!

        var item = kcdata_item()
        var payload64 : UInt64
        var payload32 : UInt32

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        item.type = UInt32(KCDATA_TYPE_CONTAINER_BEGIN)
        item.flags = 0
        item.size = UInt32(sizeof(UInt32))
        buffer.appendBytes(&item, length: sizeof(kcdata_item))
        payload32 = UInt32(STACKSHOT_KCCONTAINER_TASK)
        buffer.appendBytes(&payload32, length:sizeof(UInt32))

        item.type = UInt32(TASK_CRASHINFO_CRASHED_THREADID)
        item.flags = 0
        item.size = UInt32(sizeof(UInt64))
        buffer.appendBytes(&item, length: sizeof(kcdata_item))
        payload64 = 42
        buffer.appendBytes(&payload64, length:sizeof(UInt64))

        XCTAssert( (try? self.parseBuffer(buffer)) == nil )
    }



    func testNoEnd() {
        let buffer = NSMutableData(capacity:1000)!

        var item = kcdata_item()

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        item.type = UInt32(TASK_CRASHINFO_CRASHED_THREADID)
        item.flags = 0
        item.size = UInt32(sizeof(UInt64))
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        var payload : UInt64 = 42
        buffer.appendBytes(&payload, length:sizeof(UInt64))

        XCTAssert( (try? self.parseBuffer(buffer)) == nil )
    }


    func  testCrazySize() {
        let buffer = NSMutableData(capacity:1000)!

        var item = kcdata_item()

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        item.type = UInt32(TASK_CRASHINFO_CRASHED_THREADID)
        item.flags = 0
        item.size = 99999
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        var payload : UInt64 = 42
        buffer.appendBytes(&payload, length:sizeof(UInt64))

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        XCTAssert( (try? self.parseBuffer(buffer)) == nil )
    }

    func testReadRepeatedArray() {
        // repeated arrays should be concatenated
        let n = 10

        let buffer = NSMutableData(capacity:1000)!

        var item = kcdata_item()

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        item.type = UInt32(KCDATA_TYPE_ARRAY)
        item.flags = UInt64(TASK_CRASHINFO_CRASHED_THREADID) << 32 | UInt64(n)
        item.size = UInt32(n * sizeof(UInt64))
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        for i in 0..<n {
            var payload : UInt64 = UInt64(i)
            buffer.appendBytes(&payload, length:sizeof(UInt64))
        }

        item.type = UInt32(KCDATA_TYPE_ARRAY)
        item.flags = UInt64(TASK_CRASHINFO_CRASHED_THREADID) << 32 | UInt64(n)
        item.size = UInt32(n * sizeof(UInt64))
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        for i in 0..<n {
            var payload : UInt64 = UInt64(i)
            buffer.appendBytes(&payload, length:sizeof(UInt64))
        }

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        guard let dict = try? self.parseBuffer(buffer)
            else { XCTFail(); return }

        XCTAssert( 2*n == dict["kcdata_crashinfo"]!["crashed_threadid"]!!.count)
        for i in 0..<2*n {
            let x = dict["kcdata_crashinfo"] as? NSDictionary
            let y = x?["crashed_threadid"] as? NSArray
            XCTAssert((y?[i]) as? NSObject == i % n)
        }
    }

    func testReadThreadidArray(n : Int, pad : Int) {
        let buffer = NSMutableData(capacity:1000)!

        var item = kcdata_item()

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))
        
        item.type = UInt32(KCDATA_TYPE_ARRAY)
        item.flags = UInt64(TASK_CRASHINFO_CRASHED_THREADID) << 32 | UInt64(n)
        item.size = UInt32(n * sizeof(UInt64) + pad)
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        for i in 0..<n {
            var payload : UInt64 = UInt64(i)
            buffer.appendBytes(&payload, length:sizeof(UInt64))
        }

        for _ in 0..<pad {
            var payload : UInt8 = 0
            buffer.appendBytes(&payload, length:1)
        }

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        guard let dict = try? self.parseBuffer(buffer)
        else { XCTFail(); return; }
        
        XCTAssert( n == dict["kcdata_crashinfo"]?["crashed_threadid"]??.count)
        for i in 0..<n {
            let x = dict["kcdata_crashinfo"] as? NSDictionary
            let y = x?["crashed_threadid"] as? NSArray
            XCTAssert((y?[i]) as? NSObject == i)
        }

    }
    
    func testReadThreadidArray() {
        // test that we can correctly read old arrays with a variety of sizes and paddings
        self.testReadThreadidArray(0, pad:0)
        for n in 1..<100 {
            for pad in 0..<16 {
                self.testReadThreadidArray(n, pad:pad)
            }
        }
    }

    func testReadThreadidArrayWrongSize1() {
        /// for old style arrays, if the element size is determined by the type.   If the array of that size element at the given count doesn't fit, then parsing should fail

        let n = 1
        
        let buffer = NSMutableData(capacity:1000)!
        
        var item = kcdata_item()
        
        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))
        
        item.type = UInt32(KCDATA_TYPE_ARRAY)
        item.flags = UInt64(TASK_CRASHINFO_CRASHED_THREADID) << 32 | UInt64(n)
        item.size = UInt32(4)
        buffer.appendBytes(&item, length: sizeof(kcdata_item))
        
        var payload : UInt32 = UInt32(42)
        buffer.appendBytes(&payload, length:sizeof(UInt32))
        
        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        XCTAssert( (try? self.parseBuffer(buffer)) == nil )
    }
    
    func testReadThreadidArrayWrongSize5() {
        /// if the count is bigger than the buffer, parsing will just fail
        
        let n = 5
        
        let buffer = NSMutableData(capacity:1000)!
        
        var item = kcdata_item()
        
        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))
        
        item.type = UInt32(KCDATA_TYPE_ARRAY)
        item.flags = UInt64(TASK_CRASHINFO_CRASHED_THREADID) << 32 | UInt64(n)
        item.size = UInt32(4)
        buffer.appendBytes(&item, length: sizeof(kcdata_item))
        
        var payload : UInt32 = UInt32(42)
        buffer.appendBytes(&payload, length:sizeof(UInt32))
        
        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))
        
        XCTAssert( (try? self.parseBuffer(buffer)) == nil )
    }

    
    func testReadThreadidArrayPaddedSize() {
        // test that we can tolerate a little padding at the end of an array
        let n = 5

        let buffer = NSMutableData(capacity:1000)!

        var item = kcdata_item()

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        item.type = UInt32(KCDATA_TYPE_ARRAY)
        item.flags = UInt64(TASK_CRASHINFO_CRASHED_THREADID) << 32 | UInt64(n)
        item.size = UInt32(n * sizeof(UInt64)) + 1
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        for i in 0..<n {
            var payload : UInt64 = UInt64(i)
            buffer.appendBytes(&payload, length:sizeof(UInt64))
        }
        var payload : UInt8 = 0
        buffer.appendBytes(&payload, length:1)

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        guard let dict = try? self.parseBuffer(buffer)
        else { XCTFail(); return; }

        XCTAssert( n == dict["kcdata_crashinfo"]?["crashed_threadid"]??.count)
        for i in 0..<n {
            let x = dict["kcdata_crashinfo"] as? NSDictionary
            let y = x?["crashed_threadid"] as? NSArray
            XCTAssert((y?[i]) as? NSObject == i)
        }
    }

    func testReadThreadidArrayPaddedSize15() {
        // test that we can tolerate a little padding at the end of an array
        let n = 5

        let buffer = NSMutableData(capacity:1000)!

        var item = kcdata_item()

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        item.type = UInt32(KCDATA_TYPE_ARRAY)
        item.flags = UInt64(TASK_CRASHINFO_CRASHED_THREADID) << 32 | UInt64(n)
        item.size = UInt32(n * sizeof(UInt64)) + 15
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        for i in 0..<n {
            var payload : UInt64 = UInt64(i)
            buffer.appendBytes(&payload, length:sizeof(UInt64))
        }
        for i in 0..<15 {
            i;
            var payload : UInt8 = 0
            buffer.appendBytes(&payload, length:1)
        }

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        guard let dict = try? self.parseBuffer(buffer)
        else { XCTFail(); return; }

        XCTAssert( n == dict["kcdata_crashinfo"]?["crashed_threadid"]??.count)
        for i in 0..<n {
            let x = dict["kcdata_crashinfo"] as? NSDictionary
            let y = x?["crashed_threadid"] as? NSArray
            XCTAssert((y?[i]) as? NSObject == i)
        }
    }


    func testReadThreadidWrongSize(size : UInt32) {
        let buffer = NSMutableData(capacity:1000)!

        var item = kcdata_item()

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        item.type = UInt32(TASK_CRASHINFO_CRASHED_THREADID)
        item.flags = 0
        item.size = size
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        var payload : UInt64 = 42
        buffer.appendBytes(&payload, length:Int(size))

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.appendBytes(&item, length: sizeof(kcdata_item))

        guard let dict = try? self.parseBuffer(buffer)
        else { XCTFail(); return; }

        XCTAssert(dict["kcdata_crashinfo"]?["crashed_threadid"] == nil)
    }

    func testReadThreadidWrongSize0() {
        self.testReadThreadidWrongSize(0)
    }

    func testReadThreadidWrongSize7() {
        self.testReadThreadidWrongSize(7)
    }

    func dataWithResource(name:String) -> NSData? {
        guard let filename =  NSBundle(forClass: self.classForCoder).pathForResource(name, ofType: nil)
        else { return nil }
        return NSData(contentsOfFile:filename)!
    }
    
    func testSampleStackshot(name : String) {
        // check that we agree with sample file

        guard let sampledata = self.dataWithResource(name)
            else { XCTFail(); return }
        var dict : NSDictionary?

        dict = try? self.parseBuffer(sampledata)

        if (dict == nil) {
            if let decoded = NSData(base64EncodedData: sampledata, options:.IgnoreUnknownCharacters) {
                dict = try? self.parseBuffer(decoded)
            }
        }

        if (dict == nil) {
            if let decompressed = try? decompress(sampledata) {
                dict = try? self.parseBuffer(decompressed)
            }
        }

        if (dict == nil) {
            XCTFail(); return;
        }

        guard let plistdata = self.dataWithResource(name + ".plist.gz") ??
                              self.dataWithResource(name + ".plist")
            else {XCTFail(); return}

        var dict2 = try? NSPropertyListSerialization.propertyListWithData(plistdata, options: NSPropertyListReadOptions.Immutable, format: nil)
        if dict2 == nil {
            dict2 = try? NSPropertyListSerialization.propertyListWithData(decompress(plistdata), options: .Immutable, format: nil)
        }

        XCTAssert(dict2 != nil)

        XCTAssert(dict == dict2 as? NSDictionary)

        // check that we agree with python

        #if os(OSX)

            let kcdatapy = NSBundle(forClass: self.classForCoder).pathForResource("kcdata.py", ofType: nil)

        let task = NSTask()
        task.launchPath = kcdatapy
        task.arguments = ["-p",
                          NSBundle(forClass:self.classForCoder).pathForResource(name, ofType: nil)!]
        let pipe = NSPipe()
        task.standardOutput = pipe
        task.launch()

        let data = pipe.fileHandleForReading.readDataToEndOfFile()

            guard let dict3 = try? NSPropertyListSerialization.propertyListWithData(data, options: .Immutable, format: nil) as? NSDictionary
            else { XCTFail(); return }

        XCTAssert(dict == dict3)

        #endif
    }

    func testSampleStackshot() {
        self.testSampleStackshot("stackshot-sample")
    }

    func testSampleStackshotOldArrays() {
        self.testSampleStackshot("stackshot-sample-old-arrays")
    }

    func testSampleStackshotNewArrays() {
        self.testSampleStackshot("stackshot-sample-new-arrays")
    }

    func testSampleDeltaStackshotOldArrays() {
        self.testSampleStackshot("delta-stackshot-sample-old-arrays")
    }

    func testSampleDeltaStackshotNewArrays() {
        self.testSampleStackshot("delta-stackshot-sample-new-arrays")
    }

    func testSampleCorpse() {
        self.testSampleStackshot("corpse-sample")
    }

    func testSampleStackshotTailspin() {
        self.testSampleStackshot("stackshot-sample-tailspin")
    }

    func testSampleStackshotTailspin2() {
        self.testSampleStackshot("stackshot-sample-tailspin-2")
    }

    func testSampleExitReason() {
        self.testSampleStackshot("exitreason-sample")
    }
    
    func testSampleThreadT() {
        self.testSampleStackshot("stackshot-sample-ths-thread-t")
    }

    func testSampleCpuTimes() {
        self.testSampleStackshot("stackshot-sample-cputime")
    }

    func testSampleDuration() {
        self.testSampleStackshot("stackshot-sample-duration")
    }

    func testSampleNested() {
        self.testSampleStackshot("nested-sample")
    }

    func testSampleTermWithReason() {
        self.testSampleStackshot("test-twr-sample")
    }

    func testSampleCorpseTermWithReason() {
        self.testSampleStackshot("corpse-twr-sample")
    }

    func testSampleCorpseTermWithReasonV2() {
        self.testSampleStackshot("corpse-twr-sample-v2")
    }

    func testSampleCodesigningExitReason() {
        self.testSampleStackshot("exitreason-codesigning")
    }

    func testStackshotSharedcacheV2() {
        self.testSampleStackshot("stackshot-sample-sharedcachev2")
    }

    func testStackshotFaultStats() {
        self.testSampleStackshot("stackshot-fault-stats")
    }

    func testStackshotwithKCID() {
        self.testSampleStackshot("stackshot-with-kcid")
    }

    func testXNUPostTestConfig() {
        self.testSampleStackshot("xnupost_testconfig-sample")
    }

    func testTrivial() {
    }
}
