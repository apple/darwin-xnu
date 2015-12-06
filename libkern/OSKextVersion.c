/*
 * Copyright (c) 2000-2008 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
#ifdef KERNEL
#include <sys/systm.h>
#include <libkern/OSKextLib.h>
#include <libkern/OSKextLibPrivate.h>
#else
#include <libc.h>
#include <libkern/OSKextLib.h>
#include <System/libkern/OSKextLibPrivate.h>
#endif /* KERNEL */

#include <libkern/OSKextLibPrivate.h>

#define VERS_MAJOR_DIGITS        (4)
#define VERS_MINOR_DIGITS        (2)
#define VERS_REVISION_DIGITS     (2)
#define VERS_STAGE_DIGITS        (1)
#define VERS_STAGE_LEVEL_DIGITS  (3)

#define VERS_MAJOR_MAX           (9999)
#define VERS_STAGE_LEVEL_MAX      (255)

#define VERS_MAJOR_MULT    (100000000)
#define VERS_MINOR_MULT      (1000000)
#define VERS_REVISION_MULT     (10000)
#define VERS_STAGE_MULT         (1000)


typedef enum {
    kOSKextVersionStageInvalid     = 0,
    kOSKextVersionStageDevelopment = 1,
    kOSKextVersionStageAlpha       = 3,
    kOSKextVersionStageBeta        = 5,
    kOSKextVersionStageCandidate   = 7,
    kOSKextVersionStageRelease     = 9,
} OSKextVersionStage;


/*********************************************************************
*********************************************************************/
static int __vers_isdigit(char c) {
    return (c == '0' ||
        c == '1' || c == '2' || c == '3' ||
        c == '4' || c == '5' || c == '6' ||
        c == '7' || c == '8' || c == '9');
}

/*********************************************************************
*********************************************************************/
static int __vers_isspace(char c) {
    return (c == ' ' ||
        c == '\t' ||
        c == '\r' ||
        c == '\n');
}

/*********************************************************************
*********************************************************************/
static int __vers_digit_for_char(char c) {
    switch (c) {
      case '0': return 0; break;
      case '1': return 1; break;
      case '2': return 2; break;
      case '3': return 3; break;
      case '4': return 4; break;
      case '5': return 5; break;
      case '6': return 6; break;
      case '7': return 7; break;
      case '8': return 8; break;
      case '9': return 9; break;
      default:  return -1; break;
    }

    return -1;
}

/*********************************************************************
*********************************************************************/
static int __VERS_isreleasestate(char c) {
    return (c == 'd' || c == 'a' || c == 'b' || c == 'f');
}


/*********************************************************************
*********************************************************************/
static OSKextVersionStage __OSKextVersionStageForString(const char ** string_p) {
    const char * string;

    if (!string_p || !*string_p) {
        return kOSKextVersionStageInvalid;
    }

    string = *string_p;

    if (__vers_isspace(string[0]) || string[0] == '\0') {
        return kOSKextVersionStageRelease;
    } else {
        switch (string[0]) {
          case 'd':
              if (__vers_isdigit(string[1])) {
                  *string_p = &string[1];
                  return kOSKextVersionStageDevelopment;
              }
              break;
          case 'a':
              if (__vers_isdigit(string[1])) {
                  *string_p = &string[1];
                  return kOSKextVersionStageAlpha;
              }
              break;
          case 'b':
              if (__vers_isdigit(string[1])) {
                  *string_p = &string[1];
                  return kOSKextVersionStageBeta;
              }
              break;
          case 'f':
              if (__vers_isdigit(string[1])) {
                  *string_p = &string[1];
                  return kOSKextVersionStageCandidate;
              } else if (string[1] == 'c' && __vers_isdigit(string[2])) {
                  *string_p = &string[2];
                  return kOSKextVersionStageCandidate;
              } else {
                  return kOSKextVersionStageInvalid;
              }
              break;
          default:
              return kOSKextVersionStageInvalid;
              break;
        }
    }

    return kOSKextVersionStageInvalid;
}

/*********************************************************************
*********************************************************************/
static const char * __OSKextVersionStringForStage(OSKextVersionStage stage)
{
    switch (stage) {
      case kOSKextVersionStageInvalid:     return NULL; break;
      case kOSKextVersionStageDevelopment: return "d"; break;
      case kOSKextVersionStageAlpha:       return "a"; break;
      case kOSKextVersionStageBeta:        return "b"; break;
      case kOSKextVersionStageCandidate:   return "f"; break;
      case kOSKextVersionStageRelease:     return ""; break;
    }

    return NULL;
}

/*********************************************************************
*********************************************************************/
OSKextVersion OSKextParseVersionString(const char * versionString)
{
    OSKextVersion   result             = -1;
    int             vers_digit         = -1;
    int             num_digits_scanned = 0;
    OSKextVersion   vers_major         = 0;
    OSKextVersion   vers_minor         = 0;
    OSKextVersion   vers_revision      = 0;
    OSKextVersion   vers_stage         = 0;
    OSKextVersion   vers_stage_level   = 0;
    const char    * current_char_p;

    if (!versionString || *versionString == '\0') {
        return -1;
    }

    current_char_p = (const char *)&versionString[0];

   /*****
    * Check for an initial digit of the major release number.
    */
    vers_major = __vers_digit_for_char(*current_char_p);
    if (vers_major < 0) {
        return -1;
    }

    current_char_p++;
    num_digits_scanned = 1;

   /* Complete scan for major version number. Legal characters are
    * any digit, period, any buildstage letter.
    */
    while (num_digits_scanned < VERS_MAJOR_DIGITS) {
        if (__vers_isspace(*current_char_p) || *current_char_p == '\0') {
            vers_stage = kOSKextVersionStageRelease;
            goto finish;
        } else if (__vers_isdigit(*current_char_p)) {
            vers_digit = __vers_digit_for_char(*current_char_p);
            if (vers_digit < 0) {
                return -1;
            }
            vers_major = (vers_major) * 10 + vers_digit;
            current_char_p++;
            num_digits_scanned++;
        } else if (__VERS_isreleasestate(*current_char_p)) {
            goto release_state;
        } else if (*current_char_p == '.') {
            current_char_p++;
            goto minor_version;
        } else {
            return -1;
        }
    }

   /* Check for too many digits.
    */
    if (num_digits_scanned == VERS_MAJOR_DIGITS) {
         if (*current_char_p == '.') {
            current_char_p++;
        } else if (__vers_isdigit(*current_char_p)) {
            return -1;
        }
    }

minor_version:

    num_digits_scanned = 0;

   /* Scan for minor version number. Legal characters are
    * any digit, period, any buildstage letter.
    */
    while (num_digits_scanned < VERS_MINOR_DIGITS) {
        if (__vers_isspace(*current_char_p) || *current_char_p == '\0') {
            vers_stage = kOSKextVersionStageRelease;
            goto finish;
        } else if (__vers_isdigit(*current_char_p)) {
            vers_digit = __vers_digit_for_char(*current_char_p);
            if (vers_digit < 0) {
                return -1;
            }
            vers_minor = (vers_minor) * 10 + vers_digit;
            current_char_p++;
            num_digits_scanned++;
        } else if (__VERS_isreleasestate(*current_char_p)) {
            goto release_state;
        } else if (*current_char_p == '.') {
            current_char_p++;
            goto revision;
        } else {
            return -1;
        }
    }

   /* Check for too many digits.
    */
    if (num_digits_scanned == VERS_MINOR_DIGITS) {
         if (*current_char_p == '.') {
            current_char_p++;
        } else if (__vers_isdigit(*current_char_p)) {
            return -1;
        }
    }

revision:

    num_digits_scanned = 0;

   /* Scan for revision version number. Legal characters are
    * any digit, any buildstage letter (NOT PERIOD).
    */
    while (num_digits_scanned < VERS_REVISION_DIGITS) {
        if (__vers_isspace(*current_char_p) || *current_char_p == '\0') {
            vers_stage = kOSKextVersionStageRelease;
            goto finish;
        } else if (__vers_isdigit(*current_char_p)) {
            vers_digit = __vers_digit_for_char(*current_char_p);
            if (vers_digit < 0) {
                return -1;
            }
            vers_revision = (vers_revision) * 10 + vers_digit;
            current_char_p++;
            num_digits_scanned++;
        } else if (__VERS_isreleasestate(*current_char_p)) {
            goto release_state;
        } else {
            return -1;
        }
    }

   /* Check for too many digits.
    */
    if (num_digits_scanned == VERS_REVISION_DIGITS) {
         if (*current_char_p == '.') {
            current_char_p++;
        } else if (__vers_isdigit(*current_char_p)) {
            return -1;
        }
    }

release_state:

   /*****
    * Check for the release state.
    */
    if (__vers_isspace(*current_char_p) || *current_char_p == '\0') {
        vers_stage = kOSKextVersionStageRelease;
        goto finish;
    } else {
        vers_stage = __OSKextVersionStageForString(&current_char_p);
        if (vers_stage == kOSKextVersionStageInvalid) {
            return -1;
        }
    }


// stage level

    num_digits_scanned = 0;

   /* Scan for stage level number. Legal characters are
    * any digit only.
    */
    while (num_digits_scanned < VERS_STAGE_LEVEL_DIGITS) {
        if (__vers_isspace(*current_char_p) || *current_char_p == '\0') {
            if (num_digits_scanned) {
                goto finish;
            } else {
                return -1;
            }
        } else if (__vers_isdigit(*current_char_p)) {
            vers_digit = __vers_digit_for_char(*current_char_p);
            if (vers_digit < 0) {
                return -1;
            }
            vers_stage_level = (vers_stage_level) * 10 + vers_digit;
            current_char_p++;
            num_digits_scanned++;
        } else {
            return -1;
        }
    }

   /* Check for too many digits.
    */
    if ((num_digits_scanned == VERS_STAGE_LEVEL_DIGITS) &&
        ! (__vers_isspace(*current_char_p) || (*current_char_p == '\0'))) {

        return -1;
    }

    if (vers_stage_level > VERS_STAGE_LEVEL_MAX) {
        return -1;
    }

finish:

    if (vers_stage == kOSKextVersionStageCandidate && vers_stage_level == 0) {
        return -1;
    }

    result = (vers_major * VERS_MAJOR_MULT) +
             (vers_minor * VERS_MINOR_MULT) +
             (vers_revision * VERS_REVISION_MULT) +
             (vers_stage * VERS_STAGE_MULT) +
             vers_stage_level; 

    return result;
}

/*********************************************************************
* This function must be safe to call in panic context.
*********************************************************************/
Boolean OSKextVersionGetString(
    OSKextVersion   aVersion,
    char          * buffer,
    uint32_t        bufferLength)
{
    int             cpos = 0;
    OSKextVersion   vers_major = 0;
    OSKextVersion   vers_minor = 0;
    OSKextVersion   vers_revision = 0;
    OSKextVersion   vers_stage = 0;
    OSKextVersion   vers_stage_level = 0;
    const char    * stage_string = NULL;  // don't free

   /* No buffer or length less than longest possible vers string,
    * return 0.
    */
    if (!buffer || bufferLength < kOSKextVersionMaxLength) {
        return FALSE;
    }

    bzero(buffer, bufferLength * sizeof(char));

    if (aVersion < 0) {
        strlcpy(buffer, "(invalid)", bufferLength);
        return TRUE;
    }
    if (aVersion == 0) {
        strlcpy(buffer, "(missing)", bufferLength);
        return TRUE;
    }

    vers_major = aVersion / VERS_MAJOR_MULT;
    if (vers_major > VERS_MAJOR_MAX) {
        strlcpy(buffer, "(invalid)", bufferLength);
        return TRUE;
    }

    vers_minor = aVersion - (vers_major * VERS_MAJOR_MULT);
    vers_minor /= VERS_MINOR_MULT;

    vers_revision = aVersion -
        ( (vers_major * VERS_MAJOR_MULT) + (vers_minor * VERS_MINOR_MULT) );
    vers_revision /= VERS_REVISION_MULT;

    vers_stage = aVersion -
        ( (vers_major * VERS_MAJOR_MULT) + (vers_minor * VERS_MINOR_MULT) +
          (vers_revision * VERS_REVISION_MULT));
    vers_stage /= VERS_STAGE_MULT;

    vers_stage_level = aVersion -
        ( (vers_major * VERS_MAJOR_MULT) + (vers_minor * VERS_MINOR_MULT) +
          (vers_revision * VERS_REVISION_MULT) + (vers_stage * VERS_STAGE_MULT));
    if (vers_stage_level > VERS_STAGE_LEVEL_MAX) {
        strlcpy(buffer, "(invalid)", bufferLength);
        return TRUE;
    }

    cpos = snprintf(buffer, bufferLength, "%u", (uint32_t)vers_major);

   /* Always include the minor version; it just looks weird without.
    */
    buffer[cpos] = '.';
    cpos++;
    cpos += snprintf(buffer+cpos, bufferLength - cpos, "%u", (uint32_t)vers_minor);

   /* The revision is displayed only if nonzero.
    */
    if (vers_revision) {
        buffer[cpos] = '.';
        cpos++;
        cpos += snprintf(buffer+cpos, bufferLength - cpos, "%u",
			(uint32_t)vers_revision);
    }

    stage_string = __OSKextVersionStringForStage(vers_stage);
    if (!stage_string) {
        strlcpy(buffer, "(invalid)", bufferLength);
        return TRUE;
    }
    if (stage_string[0]) {
        strlcat(buffer, stage_string, bufferLength);
        cpos += strlen(stage_string);
    }

    if (vers_stage < kOSKextVersionStageRelease) {
        snprintf(buffer+cpos, bufferLength - cpos, "%u", (uint32_t)vers_stage_level);
    }

    return TRUE;
}

/*********************************************************************
*********************************************************************/
#ifndef KERNEL
OSKextVersion OSKextParseVersionCFString(CFStringRef versionString)
{
    OSKextVersion result = -1;
    char         versBuffer[kOSKextVersionMaxLength];
    
    if (CFStringGetCString(versionString, versBuffer,
        sizeof(versBuffer), kCFStringEncodingASCII)) {

        result = OSKextParseVersionString(versBuffer);
    }
    return result;
}
#endif
