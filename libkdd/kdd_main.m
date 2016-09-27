//
//  main.m
//  kdd command
//
//  Created by Lawrence D'Anna on 11/9/15.
//  Copyright © 2015 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#include <stdio.h>
#include <unistd.h>
#include <zlib.h>
#import "kdd.h"

void usage(char *const* argv) {
    fprintf(stderr, "usage: %s [-p] FILE\n", argv[0]);
    exit(1);
}

int main(int argc, char *const*argv) {

    int c ;
    int plist = 0;

    while ((c = getopt(argc, argv, "p")) != EOF) {
        switch(c) {
        case 'p':
            plist = TRUE;
            break;
        case '?':
        case 'h':
        default:
            usage(argv);
            break;
        }
    }

    if (optind != argc -1) {
        usage(argv);
    }

    NSError *error = nil;
    NSData *data;

    if (0 == strcmp(argv[optind], "-")) {
        data = [[NSFileHandle fileHandleWithStandardInput] readDataToEndOfFile];
    } else {
        data = [NSData dataWithContentsOfFile:[NSString stringWithUTF8String:argv[optind]]
                                      options:NSDataReadingMappedIfSafe
                                        error:&error];
    }

    if (!data || error) {
        NSLog(@"couldn't read data: %@", error);
        return 1;
    }

    if (data.length > UINT32_MAX) {
        NSLog(@"data too big");
        return 1;
    }

    NSDictionary *dict = parseKCDataBuffer((void*)data.bytes, (uint32_t)data.length, &error);

    if (error && error.code == KERN_INVALID_VALUE) {
        uint8_t buffer[100];
        z_stream stream;
        bzero(&stream, sizeof(stream));
        stream.next_in = (void*) data.bytes;
        stream.avail_in = data.length;
        stream.next_out = buffer;
        stream.avail_out = sizeof(buffer);
        inflateInit2(&stream, 16+MAX_WBITS);
        NSMutableData *inflated = [[NSMutableData alloc] init];
        while (1) {
            int z = inflate(&stream, Z_NO_FLUSH);
            if (z == Z_OK || z == Z_STREAM_END) {
                [inflated appendBytes:buffer length:sizeof(buffer) - stream.avail_out];
                stream.avail_out = sizeof(buffer);
                stream.next_out = buffer;
                if (z == Z_STREAM_END) {
                    break;
                }
            } else {
                inflated = nil;
                break;
            }
        }
        if (inflated) {
            error = nil;
            dict = parseKCDataBuffer((void*)inflated.bytes, (uint32_t)inflated.length, &error);
        }
    }

    if (error && error.code == KERN_INVALID_VALUE) {
        NSData *decoded = [[NSData alloc] initWithBase64EncodedData:data options:NSDataBase64DecodingIgnoreUnknownCharacters];
        if (decoded) {
            error = nil;
            dict = parseKCDataBuffer((void*)decoded.bytes, (uint32_t)decoded.length, &error);
        }
    }

    if (!dict || error) {
        NSLog(@"error parsing kcdata: %@", error);
        return 1;
    }

    if (plist) {
        NSData *plist = [NSPropertyListSerialization dataWithPropertyList:dict
                                                                   format:NSPropertyListXMLFormat_v1_0
                                                                  options:0
                                                                    error:&error];
        if (!plist || error) {
            NSLog(@"couldn't write plist: %@", error);
            return 1;
        }

        fwrite(plist.bytes, plist.length, 1, stdout);

    } else {
        puts([[NSString stringWithFormat: @"%@", dict] UTF8String]);
    }


    return 0;
}
