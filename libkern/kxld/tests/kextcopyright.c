#include <stdio.h>

#include <CoreFoundation/CoreFoundation.h>

#include <kxld.h>

#define kCFBundleGetInfoStringKey CFSTR("CFBundleGetInfoString")
#define kNSHumanReadableCopyrightKey CFSTR("NSHumanReadableCopyright")

const char *gProgname = NULL;

static void usage(void);
static void printFormat(void);
static char *convert_cfstring(CFStringRef the_string);

/******************************************************************************
******************************************************************************/
static void
usage(void)
{
    printf("usage: %s [path to kext]\n\n"
           "This program validates the copyright string in a kext's info "
           "dictionary.\n\n", gProgname);

    printFormat();
}

/******************************************************************************
******************************************************************************/
static void
printFormat(void)
{
    fprintf(stderr, 
        "The copyright string should be contained in the NSHumanReadableCopyright key.\n"
        "It should be of the format:\n"
        "\tCopyright © [year(s) of publication] Apple Inc. All rights reserved.\n\n"
        "where [year(s) of publication] is a comma-separated list of years and/or\n"
        "year ranges, e.g., 2004, 2006-2008.  Years must be four digits.  Year ranges\n"
        "may not contain spaces and must use four digits for both years.\n\n"
        "The following are examples of valid copyright strings:\n"
        "\tCopyright © 2008 Apple Inc. All rights reserved.\n"
        "\tCopyright © 2004-2008 Apple Inc. All rights reserved.\n"
        "\tCopyright © 1998,2000-2002,2004,2006-2008 Apple Inc. All rights reserved.\n");
}

/******************************************************************************
******************************************************************************/
char *
convert_cfstring(CFStringRef the_string)
{
    char *result = NULL;
    CFDataRef the_data = NULL;
    const UInt8 *data_bytes = NULL;
    char *converted_string = NULL;
    u_long converted_len = 0;
    u_long bytes_copied = 0;

    the_data = CFStringCreateExternalRepresentation(kCFAllocatorDefault,
        the_string, kCFStringEncodingUTF8, 0);
    if (!the_data) {
        fprintf(stderr, "Failed to convert string\n");
        goto finish;
    }

    data_bytes = CFDataGetBytePtr(the_data);
    if (!data_bytes) {
        fprintf(stderr, "Failed to get converted string bytes\n");
        goto finish;
    }

    converted_len = strlen((const char *)data_bytes) + 1; // +1 for nul
    converted_string = malloc(converted_len);
    if (!converted_string) {
        fprintf(stderr, "Failed to allocate memory\n");
        goto finish;
    }

    bytes_copied = strlcpy(converted_string, (const char *) data_bytes, 
        converted_len) + 1; // +1 for nul
    if (bytes_copied != converted_len) {
        fprintf(stderr, "Failed to copy converted string\n");
        goto finish;
    }

    result = converted_string;
finish:
    return result;
}

/******************************************************************************
******************************************************************************/
int
main(int argc, const char *argv[])
{
    int result = 1;
    boolean_t infoCopyrightIsValid = false;
    boolean_t readableCopyrightIsValid = false;
    CFURLRef anURL = NULL;                      // must release
    CFBundleRef aBundle = NULL;                 // must release
    CFDictionaryRef aDict = NULL;               // do not release
    CFStringRef infoCopyrightString = NULL;     // do not release
    CFStringRef readableCopyrightString = NULL; // do not release
    char *infoStr = NULL;                       // must free
    char *readableStr = NULL;                   // must free

    gProgname = argv[0];

    if (argc != 2) {
        usage();
        goto finish;
    }

    anURL = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault,
        (const UInt8 *) argv[1], strlen(argv[1]), /* isDirectory */ FALSE);
    if (!anURL) {
        fprintf(stderr, "Can't create path from %s\n", argv[1]);
        goto finish;
    }

    aBundle = CFBundleCreate(kCFAllocatorDefault, anURL);
    if (!aBundle) {
        fprintf(stderr, "Can't create bundle at path %s\n", argv[1]);
        goto finish;
    }

    aDict = CFBundleGetInfoDictionary(aBundle);
    if (!aDict) {
        fprintf(stderr, "Can't get info dictionary from bundle\n");
        goto finish;
    }

    infoCopyrightString = CFDictionaryGetValue(aDict, kCFBundleGetInfoStringKey);
    readableCopyrightString = CFDictionaryGetValue(aDict, kNSHumanReadableCopyrightKey);

    if (!infoCopyrightString && !readableCopyrightString) {
        fprintf(stderr, "This kext does not have a value for NSHumanReadableCopyright");
        goto finish;
    }

    if (infoCopyrightString) {
        fprintf(stderr, "Warning: This kext has a value for CFBundleGetInfoString.\n"
            "This key is obsolete, and may be removed from the kext's Info.plist.\n"
            "It has been replaced by CFBundleVersion and NSHumanReadableCopyright.\n\n");

        infoStr = convert_cfstring(infoCopyrightString);
        if (!infoStr) goto finish;

        infoCopyrightIsValid = kxld_validate_copyright_string(infoStr); 
    }

    if (readableCopyrightString) {
        readableStr = convert_cfstring(readableCopyrightString);
        if (!readableStr) goto finish;

        readableCopyrightIsValid = kxld_validate_copyright_string(readableStr);
    }

    if (!readableCopyrightIsValid) {
        if (infoCopyrightIsValid) {
            fprintf(stderr, "Warning: The copyright string in NSHumanReadableCopyright is invalid,\n"
                    "but the string in CFBundleGetInfoString is valid.  CFBundleGetInfoString is\n"
                    "obsolete.  Please migrate your copyright string to NSHumanReadableCopyright.\n\n");
        } else {
            fprintf(stderr, "Error: There is no valid copyright string for this kext.\n\n");
            printFormat(); 
            goto finish;
        }
    }

    result = 0;
finish:
    if (anURL) CFRelease(anURL);
    if (aBundle) CFRelease(aBundle);
    if (infoStr) free(infoStr);
    if (readableStr) free(readableStr);

    return result;
}

