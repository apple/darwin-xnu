/*	$FreeBSD: src/sys/crypto/rijndael/rijndael-api-fst.h,v 1.2.2.1 2001/07/03 11:01:36 ume Exp $	*/
/*	$KAME: rijndael-api-fst.h,v 1.6 2001/05/27 00:23:23 itojun Exp $	*/

/*
 * rijndael-api-fst.h   v2.3   April '2000
 *
 * Optimised ANSI C code
 *
 * #define INTERMEDIATE_VALUE_KAT to generate the Intermediate Value Known Answer Test.
 */

#ifndef __RIJNDAEL_API_FST_H
#define __RIJNDAEL_API_FST_H

#include <crypto/rijndael/rijndael-alg-fst.h>

/*  Defines:
	Add any additional defines you need
*/

#define     DIR_ENCRYPT           0 /*  Are we encrpyting?  */
#define     DIR_DECRYPT           1 /*  Are we decrpyting?  */
#define     MODE_ECB              1 /*  Are we ciphering in ECB mode?   */
#define     MODE_CBC              2 /*  Are we ciphering in CBC mode?   */
#define     MODE_CFB1             3 /*  Are we ciphering in 1-bit CFB mode? */
#define     TRUE                  1
#define     FALSE                 0
#define     BITSPERBLOCK        128 /* Default number of bits in a cipher block */

/*  Error Codes - CHANGE POSSIBLE: inclusion of additional error codes  */
#define     BAD_KEY_DIR          -1 /*  Key direction is invalid, e.g., unknown value */
#define     BAD_KEY_MAT          -2 /*  Key material not of correct length */
#define     BAD_KEY_INSTANCE     -3 /*  Key passed is not valid */
#define     BAD_CIPHER_MODE      -4 /*  Params struct passed to cipherInit invalid */
#define     BAD_CIPHER_STATE     -5 /*  Cipher in wrong state (e.g., not initialized) */
#define     BAD_BLOCK_LENGTH     -6
#define     BAD_CIPHER_INSTANCE  -7
#define     BAD_DATA             -8 /*  Data contents are invalid, e.g., invalid padding */
#define     BAD_OTHER            -9 /*  Unknown error */

/*  CHANGE POSSIBLE:  inclusion of algorithm specific defines  */
#define     MAX_KEY_SIZE         64 /* # of ASCII char's needed to represent a key */
#define     MAX_IV_SIZE          16 /* # bytes needed to represent an IV  */

/*  Typedefs:

	Typedef'ed data storage elements.  Add any algorithm specific 
parameters at the bottom of the structs as appropriate.
*/

/*  The structure for key information */
typedef struct {
    u_int8_t  direction;            /* Key used for encrypting or decrypting? */
    int   keyLen;                   /* Length of the key  */
    char  keyMaterial[MAX_KEY_SIZE+1];  /* Raw key data in ASCII, e.g., user input or KAT values */
        /*  The following parameters are algorithm dependent, replace or add as necessary  */
	int   ROUNDS;                   /* key-length-dependent number of rounds */
    int   blockLen;                 /* block length */
    union {
    	u_int8_t xkS8[RIJNDAEL_MAXROUNDS+1][4][4];	/* key schedule		*/
    	u_int32_t xkS32[RIJNDAEL_MAXROUNDS+1][4];	/* key schedule		*/
    } xKeySched;
#define	keySched	xKeySched.xkS8
} keyInstance;

/*  The structure for cipher information */
typedef struct {                    /* changed order of the components */
    u_int8_t mode;                  /* MODE_ECB, MODE_CBC, or MODE_CFB1 */
    u_int8_t IV[MAX_IV_SIZE];       /* A possible Initialization Vector for ciphering */
        /*  Add any algorithm specific parameters needed here  */
    int   blockLen;                 /* Sample: Handles non-128 bit block sizes (if available) */
} cipherInstance;

/*  Function prototypes  */
/*  CHANGED: nothing
	TODO: implement the following extensions to setup 192-bit and 256-bit block lengths:
        makeKeyEx():    parameter blockLen added
                        -- this parameter is absolutely necessary if you want to
                        setup the round keys in a variable block length setting 
	    cipherInitEx(): parameter blockLen added (for obvious reasons)		
 */

int rijndael_makeKey(keyInstance *key, u_int8_t direction, int keyLen, char *keyMaterial);

int rijndael_cipherInit(cipherInstance *cipher, u_int8_t mode, char *IV);

int rijndael_blockEncrypt(cipherInstance *cipher, keyInstance *key,
        u_int8_t *input, int inputLen, u_int8_t *outBuffer);

int rijndael_padEncrypt(cipherInstance *cipher, keyInstance *key,
		u_int8_t *input, int inputOctets, u_int8_t *outBuffer);

int rijndael_blockDecrypt(cipherInstance *cipher, keyInstance *key,
        u_int8_t *input, int inputLen, u_int8_t *outBuffer);

int rijndael_padDecrypt(cipherInstance *cipher, keyInstance *key,
		u_int8_t *input, int inputOctets, u_int8_t *outBuffer);

#ifdef INTERMEDIATE_VALUE_KAT
int rijndael_cipherUpdateRounds(cipherInstance *cipher, keyInstance *key,
        u_int8_t *input, int inputLen, u_int8_t *outBuffer, int Rounds);
#endif /* INTERMEDIATE_VALUE_KAT */

#endif /*  __RIJNDAEL_API_FST_H */
