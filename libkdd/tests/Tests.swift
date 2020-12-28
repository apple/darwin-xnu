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

func nsuuid2uuid_t(_ nsuuid : NSUUID) -> uuid_t {
    let dat = nsuuid2array(nsuuid)
    return nsarray2uuid(dat)
}

func nsarray2uuid(_ a : [Int]) -> uuid_t {
    return uuid_t(UInt8(a[0]),
                  UInt8(a[1]),
                  UInt8(a[2]),
                  UInt8(a[3]),
                  UInt8(a[4]),
                  UInt8(a[5]),
                  UInt8(a[6]),
                  UInt8(a[7]),
                  UInt8(a[8]),
                  UInt8(a[9]),
                  UInt8(a[10]),
                  UInt8(a[11]),
                  UInt8(a[12]),
                  UInt8(a[13]),
                  UInt8(a[14]),
                  UInt8(a[15]))
}

func nsuuid2array(_ uuid: NSUUID) -> [Int] {
    var ret = [Int]()
    let ptr = UnsafeMutablePointer<UInt8>.allocate(capacity: 16)
    
    defer { ptr.deallocate(capacity:16) }

    uuid.getBytes(ptr)
    for i in 0..<16 {
        ret.append(Int(ptr[i]))
    }
    return ret
}

func decompress(_ data:NSData) throws -> NSData {
    var stream = z_stream(next_in: nil, avail_in: 0, total_in: 0, next_out: nil, avail_out: 0, total_out: 0, msg: nil, state: nil, zalloc: nil, zfree: nil, opaque: nil, data_type: 0, adler: 0, reserved: 0)

    let bufsize : Int = 1000
    let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufsize)
    defer { buffer.deallocate(capacity:bufsize) }
    let output = NSMutableData()
    stream.next_out = buffer
    stream.avail_out = UInt32(bufsize)
    stream.next_in = UnsafeMutablePointer(mutating:data.bytes.assumingMemoryBound(to:Bytef.self))
    stream.avail_in = UInt32(data.length)
    inflateInit2_(&stream, 16+MAX_WBITS, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size))

    while (true) {
        let z = inflate(&stream, Z_NO_FLUSH);
        if (z == Z_OK || z == Z_STREAM_END) {
            output.append(buffer, length: bufsize - Int(stream.avail_out))
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


extension Dictionary {
    func value(forKeyPath s:String) -> Any? {
        return (self as NSDictionary).value(forKeyPath:s)
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
    
    func parseBuffer(_ buffer:NSData) throws -> [AnyHashable:Any] {
        var error : NSError?
        guard let dict = parseKCDataBuffer(UnsafeMutablePointer(mutating:buffer.bytes.assumingMemoryBound(to:UInt8.self)), UInt32(buffer.length), &error)
        else {
                XCTAssert(error != nil)
                throw error!
        }
        return dict
    }

    func testPaddingFlags(_ pad : Int) {
        let buffer = NSMutableData(capacity:1000)!

        var item = kcdata_item()

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        item.type = UInt32(KCDATA_TYPE_LIBRARY_LOADINFO)
        item.flags = UInt64(pad)
        item.size = UInt32(MemoryLayout<dyld_uuid_info_32>.size)
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        let uuid = NSUUID(uuidString: "de305d54-75b4-431b-adb2-eb6b9e546014")!

        var payload = dyld_uuid_info_32(imageLoadAddress: 42, imageUUID: nsuuid2uuid_t(uuid))
        buffer.append(&payload, length:MemoryLayout<dyld_uuid_info_32>.size)

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        guard let dict = try? self.parseBuffer(buffer)
            else { XCTFail(); return; }

        var uuidarray = nsuuid2array(uuid)
        for _ in 0..<pad {
            uuidarray.removeLast()
        }

        XCTAssert(dict.value(forKeyPath:"kcdata_crashinfo.dyld_load_info.imageLoadAddress") as? Int == 42)
        XCTAssert(dict.value(forKeyPath:"kcdata_crashinfo.dyld_load_info.imageUUID") as! [Int] == uuidarray)
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
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        item.type = UInt32(STACKSHOT_KCTYPE_BOOTARGS)
        item.flags = 0
        item.size = UInt32(s.utf8.count + 1)
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)
        s.utf8CString.withUnsafeBufferPointer({
            buffer.append($0.baseAddress!, length:s.utf8.count + 1)
        })
        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        guard let dict = try? self.parseBuffer(buffer) else { XCTFail(); return; }
        XCTAssert(dict.value(forKeyPath:"kcdata_crashinfo.boot_args") as? String == s)
    }

    func testBootArgsMissingNul() {
        let s = "hello, I am some boot args"

        let buffer = NSMutableData(capacity:1000)!

        var item = kcdata_item()

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        item.type = UInt32(STACKSHOT_KCTYPE_BOOTARGS)
        item.flags = 0
        item.size = UInt32(s.utf8.count)
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)
        s.utf8CString.withUnsafeBufferPointer({
            buffer.append($0.baseAddress!, length:s.utf8.count)
        })

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        XCTAssert( (try? self.parseBuffer(buffer)) == nil )
    }

    func testLoadInfo() {
        let buffer = NSMutableData(capacity:1000)!

        var item = kcdata_item()

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        item.type = UInt32(KCDATA_TYPE_LIBRARY_LOADINFO)
        item.flags = 0
        item.size = UInt32(MemoryLayout<dyld_uuid_info_32>.size)
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        let uuid = NSUUID(uuidString: "de305d54-75b4-431b-adb2-eb6b9e546014")!

        var payload = dyld_uuid_info_32(imageLoadAddress: 42, imageUUID: nsuuid2uuid_t(uuid))
        buffer.append(&payload, length:MemoryLayout<dyld_uuid_info_32>.size)

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        guard let dict = try? self.parseBuffer(buffer)
        else { XCTFail(); return; }

        XCTAssert(dict.value(forKeyPath:"kcdata_crashinfo.dyld_load_info.imageLoadAddress") as? Int == 42)
        XCTAssert(dict.value(forKeyPath:"kcdata_crashinfo.dyld_load_info.imageUUID") as! [Int] == nsuuid2array(uuid))
    }

    func testLoadInfoWrongSize() {
        // test what happens when a struct size is short

        let buffer = NSMutableData(capacity:1000)!

        var item = kcdata_item()

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        item.type = UInt32(KCDATA_TYPE_LIBRARY_LOADINFO)
        item.flags = 0
        item.size = UInt32(MemoryLayout<dyld_uuid_info_32>.size) - 1
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        let uuid = NSUUID(uuidString: "de305d54-75b4-431b-adb2-eb6b9e546014")!

        var payload = dyld_uuid_info_32(imageLoadAddress: 42, imageUUID: nsuuid2uuid_t(uuid))
        buffer.append(&payload, length:MemoryLayout<dyld_uuid_info_32>.size - 1)

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        guard let dict = try? self.parseBuffer(buffer)
        else { XCTFail(); return; }
        XCTAssert(dict.value(forKeyPath:"kcdata_crashinfo.dyld_load_info.imageLoadAddress") as? Int == 42)
        var uuidarray = nsuuid2array(uuid)
        uuidarray.removeLast()
        XCTAssert(dict.value(forKeyPath:"kcdata_crashinfo.dyld_load_info.imageUUID") as! [Int] == uuidarray)
    }

    func testLoadInfoWayWrongSize() {
        // test what happens when a struct size is short

        let buffer = NSMutableData(capacity:1000)!

        var item = kcdata_item()

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        item.type = UInt32(KCDATA_TYPE_LIBRARY_LOADINFO)
        item.flags = 0
        item.size = UInt32(MemoryLayout<dyld_uuid_info_32>.size) - 16
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        let uuid = NSUUID(uuidString: "de305d54-75b4-431b-adb2-eb6b9e546014")!

        var payload = dyld_uuid_info_32(imageLoadAddress: 42, imageUUID: nsuuid2uuid_t(uuid))
        buffer.append(&payload, length:MemoryLayout<dyld_uuid_info_32>.size - 16)

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)
        guard let dict = try? self.parseBuffer(buffer)
        else { XCTFail(); return; }
        XCTAssert(dict.value(forKeyPath:"kcdata_crashinfo.dyld_load_info.imageLoadAddress") as? Int == 42)
        XCTAssert(dict.value(forKeyPath:"kcdata_crashinfo.dyld_load_info.imageUUID") == nil)
    }

    func testLoadInfoPreposterousWrongSize() {
        // test what happens when a struct size is short

        let buffer = NSMutableData(capacity:1000)!

        var item = kcdata_item()

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        item.type = UInt32(KCDATA_TYPE_LIBRARY_LOADINFO)
        item.flags = 0
        item.size = UInt32(1)
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        var payload = UInt8(42)
        buffer.append(&payload, length:1)

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        guard let dict = try? self.parseBuffer(buffer)
        else { XCTFail(); return; }
        XCTAssert(dict.value(forKeyPath:"kcdata_crashinfo.dyld_load_info.imageLoadAddress") == nil)
        XCTAssert(dict.value(forKeyPath:"kcdata_crashinfo.dyld_load_info.imageUUID") == nil)
    }


    func testNewArray(n : Int, pad : Int) {
        let buffer = NSMutableData(capacity:1000)!
        var item = kcdata_item()

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        item.type = UInt32(KCDATA_TYPE_ARRAY_PAD0) + UInt32(pad)
        item.flags = UInt64(STACKSHOT_KCTYPE_DONATING_PIDS) << 32 | UInt64(n)
        item.size = UInt32(n * MemoryLayout<UInt32>.size + pad)
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        for i in 0..<n {
            var payload = UInt32(42 * i)
            buffer.append(&payload, length:MemoryLayout<UInt32>.size)
        }

        for i in 0..<pad {
            var payload = UInt8(42-i)
            buffer.append(&payload, length:MemoryLayout<UInt8>.size)
        }

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        guard let dict = try? self.parseBuffer(buffer)
        else { XCTFail(); return; }
        XCTAssert((dict.value(forKeyPath:"kcdata_crashinfo.donating_pids") as! [Any]).count == n)
        for i in 0..<n {
            let x = dict["kcdata_crashinfo"] as? NSDictionary
            let y = x?["donating_pids"] as? NSArray
            XCTAssert((y?[i]) as? Int == 42 * i)
        }
    }

    func testNewArrays() {
        self.testNewArray(n:0,pad:0)
        for i in 1..<20 {
            for pad in 0..<16 {
                self.testNewArray(n:i, pad:pad)
            }
        }
    }


    func testArrayLoadInfo(n : Int) {
        let buffer = NSMutableData(capacity:1000)!
        var item = kcdata_item()

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        item.type = UInt32(KCDATA_TYPE_ARRAY_PAD0)
        item.flags = UInt64(KCDATA_TYPE_LIBRARY_LOADINFO) << 32 | UInt64(n)
        item.size = UInt32(n * MemoryLayout<dyld_uuid_info_32>.size)
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        let uuid = NSUUID(uuidString: "de305d54-75b4-431b-adb2-eb6b9e546014")!


        for i in 0..<n {
            var payload = dyld_uuid_info_32(imageLoadAddress:UInt32(i+42), imageUUID: nsuuid2uuid_t(uuid))

            buffer.append(&payload, length:MemoryLayout<dyld_uuid_info_32>.size)
        }

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        guard let dict = try? self.parseBuffer(buffer)
        else { XCTFail(); return; }
        XCTAssert((dict.value(forKeyPath:"kcdata_crashinfo.dyld_load_info") as! [Any]).count == n)
        for i in 0..<n {
            guard let loadinfo = dict.value(forKeyPath:"kcdata_crashinfo.dyld_load_info") as? [Any]
                else { XCTFail(); return; }
            guard let loadinfo_i = loadinfo[i] as? [AnyHashable:Any]
                else { XCTFail(); return; }
            XCTAssert(loadinfo_i["imageLoadAddress"] as? Int == 42 + i)
            XCTAssert(loadinfo_i["imageUUID"] as! [Int] == nsuuid2array(uuid))
        }
    }

    func testArrayLoadInfo() {
        for n in 0..<20 {
            testArrayLoadInfo(n: n)
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
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        item.type = UInt32(KCDATA_TYPE_ARRAY_PAD0)
        item.flags = UInt64(KCDATA_TYPE_LIBRARY_LOADINFO) << 32 | UInt64(n)
        item.size = UInt32(n * (MemoryLayout<dyld_uuid_info_32>.size - wrong))
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        let uuid = NSUUID(uuidString: "de305d54-75b4-431b-adb2-eb6b9e546014")!

        for i in 0..<n {
            var payload = dyld_uuid_info_32(imageLoadAddress:UInt32(i+42), imageUUID: nsuuid2uuid_t(uuid))
            buffer.append(&payload, length:MemoryLayout<dyld_uuid_info_32>.size-wrong)
        }

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)
        var uuidarray = nsuuid2array(uuid)
        uuidarray.removeLast()

        guard let dict = try? self.parseBuffer(buffer)
            else { XCTFail(); return; }
        XCTAssert((dict.value(forKeyPath:"kcdata_crashinfo.dyld_load_info") as! [Any]).count == n)
        for i in 0..<n {
            guard let loadinfo = dict.value(forKeyPath:"kcdata_crashinfo.dyld_load_info") as? [Any]
                else { XCTFail(); return; }
            guard let loadinfo_i = loadinfo[i] as? [AnyHashable:Any]
                else { XCTFail(); return; }
            XCTAssert(loadinfo_i["imageLoadAddress"] as? Int == 42 + i)
            XCTAssert(loadinfo_i["imageUUID"] as! [Int] == uuidarray)
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
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        item.type = UInt32(KCDATA_TYPE_ARRAY_PAD0)
        item.flags = UInt64(KCDATA_TYPE_LIBRARY_LOADINFO) << 32 | UInt64(n)
        item.size = UInt32(n * (MemoryLayout<dyld_uuid_info_32>.size - wrong))
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        let uuid = NSUUID(uuidString: "de305d54-75b4-431b-adb2-eb6b9e546014")!

        for i in 0..<n {
            var payload = dyld_uuid_info_32(imageLoadAddress:UInt32(i+42), imageUUID: nsuuid2uuid_t(uuid))
            buffer.append(&payload, length:MemoryLayout<dyld_uuid_info_32>.size-wrong)
        }

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)


        guard let dict = try? self.parseBuffer(buffer)
            else { XCTFail(); return; }
        XCTAssert((dict.value(forKeyPath:"kcdata_crashinfo.dyld_load_info") as! [Any]).count == n)
        for i in 0..<n {
            guard let loadinfo = dict.value(forKeyPath:"kcdata_crashinfo.dyld_load_info") as? [Any]
                else { XCTFail(); return; }
            guard let loadinfo_i = loadinfo[i] as? [AnyHashable:Any]
                else { XCTFail(); return; }
            XCTAssert(loadinfo_i["imageLoadAddress"] as? Int == 42 + i)
            XCTAssert(loadinfo_i["imageUUID"] == nil)
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
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        item.type = UInt32(KCDATA_TYPE_ARRAY_PAD0)
        item.flags = UInt64(KCDATA_TYPE_LIBRARY_LOADINFO) << 32 | UInt64(n)
        item.size = UInt32(n * (MemoryLayout<dyld_uuid_info_32>.size - wrong))
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        for i in 0..<n {
            var payload = UInt8(42*i)
            buffer.append(&payload, length:1)
        }

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)


        guard let dict = try? self.parseBuffer(buffer)
            else { XCTFail(); return; }
        XCTAssert((dict.value(forKeyPath:"kcdata_crashinfo.dyld_load_info") as! [Any]).count == n)
        for i in 0..<n {
            guard let loadinfo = dict.value(forKeyPath:"kcdata_crashinfo.dyld_load_info") as? [Any]
                else { XCTFail(); return; }
            guard let loadinfo_i = loadinfo[i] as? [AnyHashable:Any]
                else { XCTFail(); return; }
            XCTAssert(loadinfo_i["imageLoadAddress"] == nil)
            XCTAssert(loadinfo_i["imageUUID"] == nil)
        }
    }


    func testNested() {
        let buffer = NSMutableData(capacity:1000)!

        var item = kcdata_item()

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        item.type = UInt32(TASK_CRASHINFO_CRASHED_THREADID)
        item.flags = 0
        item.size = UInt32(MemoryLayout<UInt64>.size)
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        var payload : UInt64 = 42
        buffer.append(&payload, length:MemoryLayout<UInt64>.size)

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        let buffer2 = NSMutableData(capacity:1000)!

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer2.append(&item, length: MemoryLayout<kcdata_item>.size)

        item.type = UInt32(KCDATA_TYPE_NESTED_KCDATA)
        item.flags = 0
        item.size = UInt32(buffer.length)
        buffer2.append(&item, length: MemoryLayout<kcdata_item>.size)
        buffer2.append(buffer as Data)

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer2.append(&item, length: MemoryLayout<kcdata_item>.size)

        guard let dict2 = try? self.parseBuffer(buffer2)
            else { XCTFail(); return; }

        XCTAssert(dict2.value(forKeyPath:"kcdata_crashinfo.kcdata_crashinfo.crashed_threadid") as? Int == 42)
    }


    func testReadThreadid() {
        let buffer = NSMutableData(capacity:1000)!

        var item = kcdata_item()

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        item.type = UInt32(TASK_CRASHINFO_CRASHED_THREADID)
        item.flags = 0
        item.size = UInt32(MemoryLayout<UInt64>.size)
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        var payload : UInt64 = 42
        buffer.append(&payload, length:MemoryLayout<UInt64>.size)

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        guard let dict = try? self.parseBuffer(buffer)
        else { XCTFail(); return; }

        XCTAssert(dict.value(forKeyPath:"kcdata_crashinfo.crashed_threadid") as? Int == 42)
    }


    func testRepeatedKey() {
        // test a repeated item of the same key causes error

        let buffer = NSMutableData(capacity:1000)!

        var item = kcdata_item()

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        item.type = UInt32(TASK_CRASHINFO_CRASHED_THREADID)
        item.flags = 0
        item.size = UInt32(MemoryLayout<UInt64>.size)
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        var payload : UInt64 = 42
        buffer.append(&payload, length:MemoryLayout<UInt64>.size)

        item.type = UInt32(TASK_CRASHINFO_CRASHED_THREADID)
        item.flags = 0
        item.size = UInt32(MemoryLayout<UInt64>.size)
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        payload = 42
        buffer.append(&payload, length:MemoryLayout<UInt64>.size)

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

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
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        item.type = UInt32(KCDATA_TYPE_CONTAINER_BEGIN)
        item.flags = 0
        item.size = UInt32(MemoryLayout<UInt32>.size)
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)
        payload32 = UInt32(STACKSHOT_KCCONTAINER_TASK)
        buffer.append(&payload32, length:MemoryLayout<UInt32>.size)

        item.type = UInt32(TASK_CRASHINFO_CRASHED_THREADID)
        item.flags = 0
        item.size = UInt32(MemoryLayout<UInt64>.size)
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)
        payload64 = 42
        buffer.append(&payload64, length:MemoryLayout<UInt64>.size)

        item.type = UInt32(KCDATA_TYPE_CONTAINER_END)
        item.flags = 0
        item.size = UInt32(MemoryLayout<UInt32>.size)
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)
        payload32 = UInt32(STACKSHOT_KCCONTAINER_TASK)
        buffer.append(&payload32, length:MemoryLayout<UInt32>.size)


        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        guard let dict = try? self.parseBuffer(buffer)
            else { XCTFail(); return; }

        XCTAssert(dict.value(forKeyPath: "kcdata_crashinfo.task_snapshots.0.crashed_threadid")  as? Int == 42)
    }

    func testDispatchQueueLabel() {
        let buffer = NSMutableData(capacity:1000)!

        var item = kcdata_item()
        let dql = "houston.we.had.a.problem"
        var payload32 : UInt32

        item.type = KCDATA_BUFFER_BEGIN_STACKSHOT
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        item.type = UInt32(KCDATA_TYPE_CONTAINER_BEGIN)
        item.flags = 0
        item.size = UInt32(MemoryLayout<UInt32>.size)
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)
        payload32 = UInt32(STACKSHOT_KCCONTAINER_TASK)
        buffer.append(&payload32, length:MemoryLayout<UInt32>.size)

        item.type = UInt32(KCDATA_TYPE_CONTAINER_BEGIN)
        item.flags = 0
        item.size = UInt32(MemoryLayout<UInt32>.size)
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)
        payload32 = UInt32(STACKSHOT_KCCONTAINER_THREAD)
        buffer.append(&payload32, length:MemoryLayout<UInt32>.size)

        item.type = UInt32(STACKSHOT_KCTYPE_THREAD_DISPATCH_QUEUE_LABEL)
        item.flags = 0
        item.size = UInt32(dql.utf8.count + 1)
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)
        dql.utf8CString.withUnsafeBufferPointer({
            buffer.append($0.baseAddress!, length:dql.utf8.count + 1)
        })

        item.type = UInt32(KCDATA_TYPE_CONTAINER_END)
        item.flags = 0
        item.size = UInt32(MemoryLayout<UInt32>.size)
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)
        payload32 = UInt32(STACKSHOT_KCCONTAINER_THREAD)
        buffer.append(&payload32, length:MemoryLayout<UInt32>.size)

        item.type = UInt32(KCDATA_TYPE_CONTAINER_END)
        item.flags = 0
        item.size = UInt32(MemoryLayout<UInt32>.size)
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)
        payload32 = UInt32(STACKSHOT_KCCONTAINER_TASK)
        buffer.append(&payload32, length:MemoryLayout<UInt32>.size)


        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        guard let dict = try? self.parseBuffer(buffer)
            else { XCTFail(); return; }

        XCTAssert(dict.value(forKeyPath: "kcdata_stackshot.task_snapshots.0.thread_snapshots.0.dispatch_queue_label")  as? String == dql)
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
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        item.type = UInt32(KCDATA_TYPE_CONTAINER_BEGIN)
        item.flags = 0
        item.size = UInt32(MemoryLayout<UInt32>.size)
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)
        payload32 = UInt32(STACKSHOT_KCCONTAINER_TASK)
        buffer.append(&payload32, length:MemoryLayout<UInt32>.size)

        item.type = UInt32(TASK_CRASHINFO_CRASHED_THREADID)
        item.flags = 0
        item.size = UInt32(MemoryLayout<UInt64>.size)
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)
        payload64 = 42
        buffer.append(&payload64, length:MemoryLayout<UInt64>.size)

        item.type = UInt32(KCDATA_TYPE_CONTAINER_END)
        item.flags = 0
        item.size = UInt32(MemoryLayout<UInt32>.size)
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)
        payload32 = UInt32(STACKSHOT_KCCONTAINER_TASK)
        buffer.append(&payload32, length:MemoryLayout<UInt32>.size)


        item.type = UInt32(KCDATA_TYPE_CONTAINER_BEGIN)
        item.flags = 0
        item.size = UInt32(MemoryLayout<UInt32>.size)
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)
        payload32 = UInt32(STACKSHOT_KCCONTAINER_TASK)
        buffer.append(&payload32, length:MemoryLayout<UInt32>.size)

        item.type = UInt32(TASK_CRASHINFO_CRASHED_THREADID)
        item.flags = 0
        item.size = UInt32(MemoryLayout<UInt64>.size)
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)
        payload64 = 42
        buffer.append(&payload64, length:MemoryLayout<UInt64>.size)

        item.type = UInt32(KCDATA_TYPE_CONTAINER_END)
        item.flags = 0
        item.size = UInt32(MemoryLayout<UInt32>.size)
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)
        payload32 = UInt32(STACKSHOT_KCCONTAINER_TASK)
        buffer.append(&payload32, length:MemoryLayout<UInt32>.size)

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

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
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        item.type = UInt32(KCDATA_TYPE_CONTAINER_BEGIN)
        item.flags = 0
        item.size = UInt32(MemoryLayout<UInt32>.size)
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)
        payload32 = UInt32(STACKSHOT_KCCONTAINER_TASK)
        buffer.append(&payload32, length:MemoryLayout<UInt32>.size)

        item.type = UInt32(TASK_CRASHINFO_CRASHED_THREADID)
        item.flags = 0
        item.size = UInt32(MemoryLayout<UInt64>.size)
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)
        payload64 = 42
        buffer.append(&payload64, length:MemoryLayout<UInt64>.size)

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

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
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        item.type = UInt32(KCDATA_TYPE_CONTAINER_BEGIN)
        item.flags = 0
        item.size = UInt32(MemoryLayout<UInt32>.size)
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)
        payload32 = UInt32(STACKSHOT_KCCONTAINER_TASK)
        buffer.append(&payload32, length:MemoryLayout<UInt32>.size)

        item.type = UInt32(TASK_CRASHINFO_CRASHED_THREADID)
        item.flags = 0
        item.size = UInt32(MemoryLayout<UInt64>.size)
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)
        payload64 = 42
        buffer.append(&payload64, length:MemoryLayout<UInt64>.size)

        XCTAssert( (try? self.parseBuffer(buffer)) == nil )
    }



    func testNoEnd() {
        let buffer = NSMutableData(capacity:1000)!

        var item = kcdata_item()

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        item.type = UInt32(TASK_CRASHINFO_CRASHED_THREADID)
        item.flags = 0
        item.size = UInt32(MemoryLayout<UInt64>.size)
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        var payload : UInt64 = 42
        buffer.append(&payload, length:MemoryLayout<UInt64>.size)

        XCTAssert( (try? self.parseBuffer(buffer)) == nil )
    }


    func  testCrazySize() {
        let buffer = NSMutableData(capacity:1000)!

        var item = kcdata_item()

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        item.type = UInt32(TASK_CRASHINFO_CRASHED_THREADID)
        item.flags = 0
        item.size = 99999
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        var payload : UInt64 = 42
        buffer.append(&payload, length:MemoryLayout<UInt64>.size)

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

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
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        item.type = UInt32(KCDATA_TYPE_ARRAY)
        item.flags = UInt64(TASK_CRASHINFO_CRASHED_THREADID) << 32 | UInt64(n)
        item.size = UInt32(n * MemoryLayout<UInt64>.size)
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        for i in 0..<n {
            var payload : UInt64 = UInt64(i)
            buffer.append(&payload, length:MemoryLayout<UInt64>.size)
        }

        item.type = UInt32(KCDATA_TYPE_ARRAY)
        item.flags = UInt64(TASK_CRASHINFO_CRASHED_THREADID) << 32 | UInt64(n)
        item.size = UInt32(n * MemoryLayout<UInt64>.size)
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        for i in 0..<n {
            var payload : UInt64 = UInt64(i)
            buffer.append(&payload, length:MemoryLayout<UInt64>.size)
        }

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        guard let dict = try? self.parseBuffer(buffer)
            else { XCTFail(); return }

        XCTAssert( 2*n == (dict.value(forKeyPath:"kcdata_crashinfo.crashed_threadid") as! [Any]).count)
        for i in 0..<2*n {
            let x = dict["kcdata_crashinfo"] as? NSDictionary
            let y = x?["crashed_threadid"] as? NSArray
            XCTAssert((y?[i]) as? Int == i % n)
        }
    }

    func testReadThreadidArray(n : Int, pad : Int) {
        let buffer = NSMutableData(capacity:1000)!

        var item = kcdata_item()

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        item.type = UInt32(KCDATA_TYPE_ARRAY)
        item.flags = UInt64(TASK_CRASHINFO_CRASHED_THREADID) << 32 | UInt64(n)
        item.size = UInt32(n * MemoryLayout<UInt64>.size + pad)
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        for i in 0..<n {
            var payload : UInt64 = UInt64(i)
            buffer.append(&payload, length:MemoryLayout<UInt64>.size)
        }

        for _ in 0..<pad {
            var payload : UInt8 = 0
            buffer.append(&payload, length:1)
        }

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        guard let dict = try? self.parseBuffer(buffer)
        else { XCTFail(); return; }

        XCTAssert( n == (dict.value(forKeyPath:"kcdata_crashinfo.crashed_threadid") as! [Any]).count)

        for i in 0..<n {
            let x = dict["kcdata_crashinfo"] as? NSDictionary
            let y = x?["crashed_threadid"] as? NSArray
            XCTAssert((y?[i]) as? Int == i)
        }

    }

    func testReadThreadidArray() {
        // test that we can correctly read old arrays with a variety of sizes and paddings
        self.testReadThreadidArray(n: 0, pad:0)
        for n in 1..<100 {
            for pad in 0..<16 {
                self.testReadThreadidArray(n: n, pad:pad)
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
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        item.type = UInt32(KCDATA_TYPE_ARRAY)
        item.flags = UInt64(TASK_CRASHINFO_CRASHED_THREADID) << 32 | UInt64(n)
        item.size = UInt32(4)
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        var payload : UInt32 = UInt32(42)
        buffer.append(&payload, length:MemoryLayout<UInt32>.size)

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

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
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        item.type = UInt32(KCDATA_TYPE_ARRAY)
        item.flags = UInt64(TASK_CRASHINFO_CRASHED_THREADID) << 32 | UInt64(n)
        item.size = UInt32(4)
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        var payload : UInt32 = UInt32(42)
        buffer.append(&payload, length:MemoryLayout<UInt32>.size)

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

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
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        item.type = UInt32(KCDATA_TYPE_ARRAY)
        item.flags = UInt64(TASK_CRASHINFO_CRASHED_THREADID) << 32 | UInt64(n)
        item.size = UInt32(n * MemoryLayout<UInt64>.size) + 1
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        for i in 0..<n {
            var payload : UInt64 = UInt64(i)
            buffer.append(&payload, length:MemoryLayout<UInt64>.size)
        }
        var payload : UInt8 = 0
        buffer.append(&payload, length:1)

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        guard let dict = try? self.parseBuffer(buffer)
        else { XCTFail(); return; }

        XCTAssert( n == (dict.value(forKeyPath:"kcdata_crashinfo.crashed_threadid") as! [Any]).count)
        for i in 0..<n {
            let x = dict["kcdata_crashinfo"] as? NSDictionary
            let y = x?["crashed_threadid"] as? NSArray
            XCTAssert((y?[i]) as? Int == i)
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
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        item.type = UInt32(KCDATA_TYPE_ARRAY)
        item.flags = UInt64(TASK_CRASHINFO_CRASHED_THREADID) << 32 | UInt64(n)
        item.size = UInt32(n * MemoryLayout<UInt64>.size) + 15
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        for i in 0..<n {
            var payload : UInt64 = UInt64(i)
            buffer.append(&payload, length:MemoryLayout<UInt64>.size)
        }
        for _ in 0..<15 {
            var payload : UInt8 = 0
            buffer.append(&payload, length:1)
        }

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        guard let dict = try? self.parseBuffer(buffer)
        else { XCTFail(); return; }

        XCTAssert( n == (dict.value(forKeyPath:"kcdata_crashinfo.crashed_threadid") as! [Any]).count)
        for i in 0..<n {
            let x = dict["kcdata_crashinfo"] as? NSDictionary
            let y = x?["crashed_threadid"] as? NSArray
            XCTAssert((y?[i]) as? Int == i)
        }
    }


    func testReadThreadidWrongSize(size : UInt32) {
        let buffer = NSMutableData(capacity:1000)!

        var item = kcdata_item()

        item.type = KCDATA_BUFFER_BEGIN_CRASHINFO
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        item.type = UInt32(TASK_CRASHINFO_CRASHED_THREADID)
        item.flags = 0
        item.size = size
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        var payload : UInt64 = 42
        buffer.append(&payload, length:Int(size))

        item.type = KCDATA_TYPE_BUFFER_END
        item.flags = 0
        item.size = 0
        buffer.append(&item, length: MemoryLayout<kcdata_item>.size)

        guard let dict = try? self.parseBuffer(buffer)
        else { XCTFail(); return; }

        XCTAssert(dict.value(forKeyPath:"kcdata_crashinfo.crashed_threadid") == nil)
    }

    func testReadThreadidWrongSize0() {
        self.testReadThreadidWrongSize(size: 0)
    }

    func testReadThreadidWrongSize7() {
        self.testReadThreadidWrongSize(size: 7)
    }

    func dataWithResource(_ name:String) -> NSData? {
        guard let filename =  Bundle(for: self.classForCoder).path(forResource: name, ofType: nil)
        else { return nil }
        return NSData(contentsOfFile:filename)!
    }

    func testSampleStackshot(_ name : String) {
        // check that we agree with sample file

        guard let sampledata = self.dataWithResource(name)
            else { XCTFail("failed to open bundle resource named " + name); return }
        var dict : NSDictionary?

        dict = try? self.parseBuffer(sampledata) as NSDictionary

        if (dict == nil) {
            if let decoded = NSData(base64Encoded: sampledata as Data, options:.ignoreUnknownCharacters) {
                dict = try? self.parseBuffer(decoded) as NSDictionary
            }
        }

        if (dict == nil) {
            if let decompressed = try? decompress(sampledata) {
                dict = try? self.parseBuffer(decompressed) as NSDictionary
            }
        }

        if (dict == nil) {
            XCTFail(); return;
        }

        guard let plistdata = self.dataWithResource(name + ".plist.gz") ??
                              self.dataWithResource(name + ".plist")
            else {XCTFail(); return}

        var opt_dict2 = try? PropertyListSerialization.propertyList(from: plistdata as Data, options: [], format: nil)
        if opt_dict2 == nil {
            opt_dict2 = try? PropertyListSerialization.propertyList(from:decompress(plistdata) as Data, options:[], format: nil)
        }
        guard let dict2 = opt_dict2
            else { XCTFail(); return}

        XCTAssertEqual(dict, dict2 as! NSDictionary);

        //XCTAssert(dict == dict2 as? NSDictionary)

        // check that we agree with python

        #if os(OSX)

            let kcdatapy = Bundle(for: self.classForCoder).path(forResource: "kcdata.py", ofType: nil)

        let task = Process()
        task.launchPath = kcdatapy
        task.arguments = ["-p",
                          Bundle(for:self.classForCoder).path(forResource: name, ofType: nil)!]
        let pipe = Pipe()
        task.standardOutput = pipe
        task.launch()

        let data = pipe.fileHandleForReading.readDataToEndOfFile()

            guard let dict3 = try? PropertyListSerialization.propertyList(from:data, options:[], format: nil) as? NSDictionary
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

    func testSampleThreadGroups() {
        self.testSampleStackshot("stackshot-sample-thread-groups")
    }

    func testSampleThreadGroupsFlags() {
        self.testSampleStackshot("stackshot-sample-thread-groups-flags")
    }

    func testSampleCoalitions() {
        self.testSampleStackshot("stackshot-sample-coalitions")
    }

    func testSampleTurnstileInfo() {
        self.testSampleStackshot("stackshot-sample-turnstileinfo")
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

    func testStackshotWithWaitinfo() {
        self.testSampleStackshot("stackshot-with-waitinfo")
    }

    func testStackshotWithThreadPolicy() {
        self.testSampleStackshot("stackshot-sample-thread-policy")
    }

    func testDeltaStackshotWithThreadPolicy() {
        self.testSampleStackshot("stackshot-sample-delta-thread-policy")
    }

    func testStackshotWithInstrsCycles() {
        self.testSampleStackshot("stackshot-sample-instrs-cycles")
    }

    func testStackshotWithStacktop() {
        self.testSampleStackshot("stackshot-sample-stacktop")
    }

    func testStackshotWithASID() {
        self.testSampleStackshot("stackshot-sample-asid")
    }

    func testStackshotWithPageTables() {
        self.testSampleStackshot("stackshot-sample-asid-pagetable")
    }

    func testStackshotCPUTimes() {
        self.testSampleStackshot("stackshot-sample-cpu-times")
    }
    
    func testStackshotWithSharedCacheLayout() {
        self.testSampleStackshot("stackshot-with-shared-cache-layout")
    }

    func testStackshotDispatchQueueLabel() {
        self.testSampleStackshot("stackshot-sample-dispatch-queue-label")
    }

    func testTrivial() {
    }
}
