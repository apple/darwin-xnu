#include <libsa/vers_rsrc.h>
#include <sys/systm.h>
#include <libkern/OSByteOrder.h>


int isdigit(char c) {
    return (c == '0' ||
        c == '1' || c == '2' || c == '3' ||
        c == '4' || c == '5' || c == '6' ||
        c == '7' || c == '8' || c == '9');
}

int isspace(char c) {
    return (c == ' ' ||
        c == '\t' ||
        c == '\r' ||
        c == '\n');
}


int isreleasestate(char c) {
    return (c == 'd' || c == 'a' || c == 'b' || c == 'f');
}


UInt8 BCD_digit_for_char(char c) {
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
      default:  return BCD_illegal; break;
    }
    return BCD_illegal;
}


char BCD_char_for_digit(UInt8 digit) {
    switch (digit) {
      case 0:  return '0'; break;
      case 1:  return '1'; break;
      case 2:  return '2'; break;
      case 3:  return '3'; break;
      case 4:  return '4'; break;
      case 5:  return '5'; break;
      case 6:  return '6'; break;
      case 7:  return '7'; break;
      case 8:  return '8'; break;
      case 9:  return '9'; break;
      default: return '?'; break;
    }
    return '?';
}


VERS_revision VERS_revision_for_string(const char ** string_p) {
    const char * string;

    if (!string_p || !*string_p) {
        return VERS_invalid;
    }

    string = *string_p;

    if (isspace(string[0]) || string[0] == '\0') {
        return VERS_release;
    } else {
        switch (string[0]) {
          case 'd':
              if (isdigit(string[1])) {
                  *string_p = &string[1];
                  return VERS_development;
              }
              break;
          case 'a':
              if (isdigit(string[1])) {
                  *string_p = &string[1];
                  return VERS_alpha;
              }
              break;
          case 'b':
              if (isdigit(string[1])) {
                  *string_p = &string[1];
                  return VERS_beta;
              }
              break;
          case 'f':
              if (isdigit(string[1])) {
                  *string_p = &string[1];
                  return VERS_candidate;
              } else if (string[1] == 'c' && isdigit(string[2])) {
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


int VERS_parse_string(const char * vers_string, UInt32 * version_num) {
    int result = 1;
    VERS_version vers;
    const char * current_char_p;
    UInt8  scratch;

    if (!vers_string || *vers_string == '\0') {
        return 0;
    }

    vers.vnum = 0;

    current_char_p = &vers_string[0];


   /*****
    * Check for an initial digit of the major release number.
    */
    vers.bytes[0] = BCD_digit_for_char(*current_char_p);
    if (vers.bytes[0] == BCD_illegal) {
        return 0;
    }

    current_char_p++;


   /*****
    * Check for a second digit of the major release number.
    */
    if (*current_char_p == '\0') {
        vers.bytes[2] = VERS_release;
        vers.bytes[3] = 0xff;
        goto finish;
    } else if (isdigit(*current_char_p)) {
        scratch = BCD_digit_for_char(*current_char_p);
        if (scratch == BCD_illegal) {
            return 0;
        }
        vers.bytes[0] = BCD_combine(vers.bytes[0], scratch);
        current_char_p++;

        if (*current_char_p == '\0') {
            vers.bytes[2] = VERS_release;
            vers.bytes[3] = 0xff;
            goto finish;
        } else if (isreleasestate(*current_char_p)) {
            goto release_state;
        } else if (*current_char_p == '.') {
            current_char_p++;
        } else {
            return 0;
        }
    } else if (isreleasestate(*current_char_p)) {
        goto release_state;
    } else if (*current_char_p == '.') {
        current_char_p++;
    } else {
        return 0;
    }


   /*****
    * Check for the minor release number.
    */
    if (*current_char_p == '\0') {
        vers.bytes[2] = VERS_release;
        vers.bytes[3] = 0xff;
        goto finish;
    } else if (isdigit(*current_char_p)) {
        vers.bytes[1] = BCD_digit_for_char(*current_char_p);
        if (vers.bytes[1] == BCD_illegal) {
            return 0;
        }

        // Make sure its the first nibble of byte 1!
        vers.bytes[1] = BCD_combine(vers.bytes[1], 0);

        current_char_p++;

        if (*current_char_p == '\0') {
            vers.bytes[2] = VERS_release;
            vers.bytes[3] = 0xff;
            goto finish;
        } else if (isreleasestate(*current_char_p)) {
            goto release_state;
        } else if (*current_char_p == '.') {
            current_char_p++;
        } else {
            return 0;
        }
    } else {
        return 0;
    }


   /*****
    * Check for the bugfix number.
    */
    if (*current_char_p == '\0') {
        vers.bytes[2] = VERS_release;
        vers.bytes[3] = 0xff;
        goto finish;
    } else if (isdigit(*current_char_p)) {
        scratch = BCD_digit_for_char(*current_char_p);
        if (scratch == BCD_illegal) {
            return 0;
        }

        /* vers.bytes[1] has its left nibble set already */
        vers.bytes[1] = vers.bytes[1] | scratch;

        current_char_p++;

        if (*current_char_p == '\0') {
            vers.bytes[2] = VERS_release;
            vers.bytes[3] = 0xff;
            goto finish;
        } else if (isreleasestate(*current_char_p)) {
            goto release_state;
        } else {
            return 0;
        }
    } else {
        return 0;
    }


release_state:

   /*****
    * Check for the release state.
    */
    if (*current_char_p == '\0') {
        vers.bytes[2] = VERS_release;
        vers.bytes[3] = 0xff;
        goto finish;
    } else {
        vers.bytes[2] = VERS_revision_for_string(&current_char_p);
        if (vers.bytes[2] == VERS_invalid) {
            return 0;
        }
    }


   /*****
    * Get the nonrelease revision number (0..255).
    */
    if (vers.bytes[2] != VERS_release) {
        UInt32 revision_num = 0;
        int    i;

        if (*current_char_p == '\0' || !isdigit(*current_char_p)) {
            return 0;
        }
        for (i = 0; i < 3 && *current_char_p != '\0'; i++, current_char_p++) {
            UInt8 scratch_digit;
            scratch_digit = BCD_digit_for_char(*current_char_p);
            if (scratch_digit == BCD_illegal) {
                return 0;
            }
            revision_num *= 10;
            revision_num += scratch_digit;
        }
        if (isdigit(*current_char_p) || revision_num > 255) {
            return 0;
        }
        vers.bytes[3] = (UInt8)revision_num;
    }

    if (vers.bytes[2] == VERS_release) {
        vers.bytes[3] = 0xff;
    } else {
        if (vers.bytes[2] == VERS_candidate) {
            if (vers.bytes[3] == 0) {
                return 0;
            } else {
                vers.bytes[2] = VERS_release;
                vers.bytes[3]--;
            }
        }
    }

finish:
    *version_num = OSSwapBigToHostInt32(vers.vnum);
    return result;
}


#define VERS_STRING_MAX_LEN  (12)

int VERS_string(char * buffer, UInt32 length, UInt32 vers) {
    VERS_version version;
    int cpos = 0;
    int result = 1;

    char major1;
    char major2;
    char minor;
    char bugfix;

    version.vnum = OSSwapHostToBigInt32(vers);

   /* No buffer, length less than longest possible vers string,
    * return 0.
    */
    if (!buffer || length < VERS_STRING_MAX_LEN) {
        result = -1;
        goto finish;
    }

    bzero(buffer, length * sizeof(char));


   /*****
    * Major version number.
    */
    major1 = BCD_char_for_digit(BCD_get_left(version.bytes[0]));
    if (major1 == '?') {
        result = 0;
    } /* this is not an 'else' situation */
    if (major1 != '0') {
        buffer[cpos] = major1;
        cpos++;
    }

    major2 = BCD_char_for_digit(BCD_get_right(version.bytes[0]));
    if (major2 == '?') {
        result = 0;
    }

    buffer[cpos] = major2;
    cpos++;


   /*****
    * Minor & bug-fix version numbers.
    */
    minor = BCD_char_for_digit(BCD_get_left(version.bytes[1]));
    if (minor == '?') {
        result = 0;
    }
    bugfix = BCD_char_for_digit(BCD_get_right(version.bytes[1]));
    if (bugfix == '?') {
        result = 0;
    }


   /* Always display the minor version number.
    */
    buffer[cpos] = '.';
    cpos++;
    buffer[cpos] = minor;
    cpos++;


   /* Only display the bugfix version number if it's nonzero.
    */
    if (bugfix != '0') {
        buffer[cpos] = '.';
        cpos++;
        buffer[cpos] = bugfix;
        cpos++;
    }


   /* If the release state is final, we're done!
    */
    if (version.bytes[2] == VERS_release && version.bytes[3] == 255) {
        result = 0;
        goto finish;
    }


   /*****
    * Do the release state and update level.
    */
    switch (version.bytes[2]) {
      case VERS_development:
        buffer[cpos] = 'd';
        cpos++;
        break;
      case VERS_alpha:
        buffer[cpos] = 'a';
        cpos++;
        break;
      case VERS_beta:
        buffer[cpos] = 'b';
        cpos++;
        break;
      case VERS_release: 
        if (version.bytes[3] < 255) {
            buffer[cpos] = 'f';
            buffer[cpos+1] = 'c';
            cpos += 2;
        } else {
            result = 1;
            goto finish;
        }
        break;
      default:
        result = 0;
        buffer[cpos] = '?';
        cpos++;
        break;
    }

    if (version.bytes[2] != VERS_release) {
        sprintf(&buffer[cpos], "%d", version.bytes[3]);
    } else {
        if (version.bytes[3] < 255) {
            sprintf(&buffer[cpos], "%d", version.bytes[3] + 1);
        }
    }

finish:
    return result;
}
