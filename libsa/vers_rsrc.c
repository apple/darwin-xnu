/*
 * Copyright (c) 2006 Apple Computer, Inc. All rights reserved.
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
#ifndef KERNEL
#include <libc.h>
#include "vers_rsrc.h"
#else
#include <sys/systm.h>
#include <libsa/vers_rsrc.h>
#endif /* not KERNEL */

#ifndef KERNEL
#define PRIV_EXT
#else
#define PRIV_EXT  __private_extern__
#endif /* not KERNEL */

#define VERS_MAJOR_DIGITS        (4)
#define VERS_MINOR_DIGITS        (2)
#define VERS_REVISION_DIGITS     (2)
#define VERS_STAGE_DIGITS        (1)
#define VERS_STAGE_LEVEL_DIGITS  (3)

#define VERS_MAJOR_MULT    (100000000)
#define VERS_MINOR_MULT      (1000000)
#define VERS_REVISION_MULT     (10000)
#define VERS_STAGE_MULT         (1000)

typedef enum {
    VERS_invalid     = 0,
    VERS_development = 1,
    VERS_alpha       = 3,
    VERS_beta        = 5,
    VERS_candidate   = 7,
    VERS_release     = 9,
} VERS_stage;


static int __vers_isdigit(char c) {
    return (c == '0' ||
        c == '1' || c == '2' || c == '3' ||
        c == '4' || c == '5' || c == '6' ||
        c == '7' || c == '8' || c == '9');
}

static int __vers_isspace(char c) {
    return (c == ' ' ||
        c == '\t' ||
        c == '\r' ||
        c == '\n');
}

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

static int __VERS_isreleasestate(char c) {
    return (c == 'd' || c == 'a' || c == 'b' || c == 'f');
}


static VERS_stage __VERS_stage_for_string(const char ** string_p) {
    const char * string;

    if (!string_p || !*string_p) {
        return VERS_invalid;
    }

    string = *string_p;

    if (__vers_isspace(string[0]) || string[0] == '\0') {
        return VERS_release;
    } else {
        switch (string[0]) {
          case 'd':
              if (__vers_isdigit(string[1])) {
                  *string_p = &string[1];
                  return VERS_development;
              }
              break;
          case 'a':
              if (__vers_isdigit(string[1])) {
                  *string_p = &string[1];
                  return VERS_alpha;
              }
              break;
          case 'b':
              if (__vers_isdigit(string[1])) {
                  *string_p = &string[1];
                  return VERS_beta;
              }
              break;
          case 'f':
              if (__vers_isdigit(string[1])) {
                  *string_p = &string[1];
                  return VERS_candidate;
              } else if (string[1] == 'c' && __vers_isdigit(string[2])) {
                  *string_p = &string[2];
                  return VERS_candidate;
              } else {
                  return VERS_invalid;
              }
              break;
          default:
              return VERS_invalid;
              break;
        }
    }

    return VERS_invalid;
}

static const char * __VERS_string_for_stage(VERS_stage stage) {
    switch (stage) {
      case VERS_invalid:     return "?"; break;
      case VERS_development: return "d"; break;
      case VERS_alpha:       return "a"; break;
      case VERS_beta:        return "b"; break;
      case VERS_candidate:   return "f"; break;
      case VERS_release:     return ""; break;
    }

    return "?";
}

PRIV_EXT
VERS_version VERS_parse_string(const char * vers_string) {
    VERS_version result = -1;
    int vers_digit = -1;
    int num_digits_scanned = 0;
    VERS_version vers_major = 0;
    VERS_version vers_minor = 0;
    VERS_version vers_revision = 0;
    VERS_version vers_stage = 0;
    VERS_version vers_stage_level = 0;
    const char * current_char_p;

    if (!vers_string || *vers_string == '\0') {
        return -1;
    }

    current_char_p = (const char *)&vers_string[0];

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
            vers_stage = VERS_release;
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
            vers_stage = VERS_release;
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
            vers_stage = VERS_release;
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
        vers_stage = VERS_release;
        goto finish;
    } else {
        vers_stage = __VERS_stage_for_string(&current_char_p);
        if (vers_stage == VERS_invalid) {
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

    if (vers_stage_level > 255) {
        return -1;
    }

finish:

    if (vers_stage == VERS_candidate && vers_stage_level == 0) {
        return -1;
    }

    result = (vers_major * VERS_MAJOR_MULT) +
             (vers_minor * VERS_MINOR_MULT) +
             (vers_revision * VERS_REVISION_MULT) +
             (vers_stage * VERS_STAGE_MULT) +
             vers_stage_level; 

    return result;
}

#define VERS_STRING_MAX_LEN  (16)

PRIV_EXT
int VERS_string(char * buffer, UInt32 length, VERS_version vers) {
    int cpos = 0;
    VERS_version vers_major = 0;
    VERS_version vers_minor = 0;
    VERS_version vers_revision = 0;
    VERS_version vers_stage = 0;
    VERS_version vers_stage_level = 0;
    const char * stage_string = NULL;  // don't free

   /* No buffer or length less than longest possible vers string,
    * return 0.
    */
    if (!buffer || length < VERS_STRING_MAX_LEN) {
        return 0;
    }

    bzero(buffer, length * sizeof(char));

    if (vers < 0) {
        strlcpy(buffer, "(invalid)", length);
        return 1;
    }

    vers_major = vers / VERS_MAJOR_MULT;

    vers_minor = vers - (vers_major * VERS_MAJOR_MULT);
    vers_minor /= VERS_MINOR_MULT;

    vers_revision = vers -
        ( (vers_major * VERS_MAJOR_MULT) + (vers_minor * VERS_MINOR_MULT) );
    vers_revision /= VERS_REVISION_MULT;

    vers_stage = vers -
        ( (vers_major * VERS_MAJOR_MULT) + (vers_minor * VERS_MINOR_MULT) +
          (vers_revision * VERS_REVISION_MULT));
    vers_stage /= VERS_STAGE_MULT;

    vers_stage_level = vers -
        ( (vers_major * VERS_MAJOR_MULT) + (vers_minor * VERS_MINOR_MULT) +
          (vers_revision * VERS_REVISION_MULT) + (vers_stage * VERS_STAGE_MULT));

    cpos = snprintf(buffer, length, "%lu", (UInt32)vers_major);

   /* Always include the minor version; it just looks weird without.
    */
    buffer[cpos] = '.';
    cpos++;
    cpos += snprintf(buffer+cpos, length - cpos, "%lu", (UInt32)vers_minor);

   /* The revision is displayed only if nonzero.
    */
    if (vers_revision) {
        buffer[cpos] = '.';
        cpos++;
        cpos += snprintf(buffer+cpos, length - cpos, "%lu",
			(UInt32)vers_revision);
    }

    stage_string = __VERS_string_for_stage(vers_stage);
    if (stage_string && stage_string[0]) {
        strlcat(buffer, stage_string, length);
        cpos += strlen(stage_string);
    }

    if (vers_stage < VERS_release) {
        snprintf(buffer+cpos, length - cpos, "%lu", (UInt32)vers_stage_level);
    }

    return 1;
}
