/*	$FreeBSD: src/sys/crypto/rijndael/rijndael-api-fst.c,v 1.2.2.1 2001/07/03 11:01:35 ume Exp $	*/
/*	$KAME: rijndael-api-fst.c,v 1.10 2001/05/27 09:34:18 itojun Exp $	*/

/*
 * rijndael-api-fst.c   v2.3   April '2000
 *
 * Optimised ANSI C code
 *
 * authors: v1.0: Antoon Bosselaers
 *          v2.0: Vincent Rijmen
 *          v2.1: Vincent Rijmen
 *          v2.2: Vincent Rijmen
 *          v2.3: Paulo Barreto
 *          v2.4: Vincent Rijmen
 *
 * This code is placed in the public domain.
 */

#include <sys/param.h>
#include <sys/types.h>
#ifdef KERNEL
#include <sys/systm.h>
#else
#include <string.h>
#endif
#include <crypto/rijndael/rijndael-alg-fst.h>
#include <crypto/rijndael/rijndael-api-fst.h>
#include <crypto/rijndael/rijndael_local.h>

int rijndael_makeKey(keyInstance *key, BYTE direction, int keyLen, char *keyMaterial) {
	word8 k[MAXKC][4];
	int i;
	char *keyMat;
	
	if (key == NULL) {
		return BAD_KEY_INSTANCE;
	}

	if ((direction == DIR_ENCRYPT) || (direction == DIR_DECRYPT)) {
		key->direction = direction;
	} else {
		return BAD_KEY_DIR;
	}

	if ((keyLen == 128) || (keyLen == 192) || (keyLen == 256)) { 
		key->keyLen = keyLen;
	} else {
		return BAD_KEY_MAT;
	}

	if (keyMaterial != NULL) {
		bcopy(keyMaterial, key->keyMaterial, keyLen/8);
	}

	key->ROUNDS = keyLen/32 + 6;

	/* initialize key schedule: */
	keyMat = key->keyMaterial;
	for (i = 0; i < key->keyLen/8; i++) {
		k[i >> 2][i & 3] = (word8)keyMat[i]; 
	}
	rijndaelKeySched(k, key->keySched, key->ROUNDS);
	if (direction == DIR_DECRYPT) {
		rijndaelKeyEncToDec(key->keySched, key->ROUNDS);
	}

	return TRUE;
}

int rijndael_cipherInit(cipherInstance *cipher, BYTE mode, char *IV) {
	if ((mode == MODE_ECB) || (mode == MODE_CBC) || (mode == MODE_CFB1)) {
		cipher->mode = mode;
	} else {
		return BAD_CIPHER_MODE;
	}
	if (IV != NULL) {
		bcopy(IV, cipher->IV, MAX_IV_SIZE);
	} else {
		bzero(cipher->IV, MAX_IV_SIZE);
	}
	return TRUE;
}

int rijndael_blockEncrypt(cipherInstance *cipher, keyInstance *key,
		BYTE *input, int inputLen, BYTE *outBuffer) {
	int i, k, numBlocks;
	word8 block[16], iv[4][4];

	if (cipher == NULL ||
		key == NULL ||
		key->direction == DIR_DECRYPT) {
		return BAD_CIPHER_STATE;
	}
	if (input == NULL || inputLen <= 0) {
		return 0; /* nothing to do */
	}

	numBlocks = inputLen/128;
	
	switch (cipher->mode) {
	case MODE_ECB: 
		for (i = numBlocks; i > 0; i--) {
			rijndaelEncrypt(input, outBuffer, key->keySched, key->ROUNDS);
			input += 16;
			outBuffer += 16;
		}
		break;
		
	case MODE_CBC:
#if 1 /*STRICT_ALIGN*/
		bcopy(cipher->IV, block, 16);
		bcopy(input, iv, 16);
		((word32*)block)[0] ^= ((word32*)iv)[0];
		((word32*)block)[1] ^= ((word32*)iv)[1];
		((word32*)block)[2] ^= ((word32*)iv)[2];
		((word32*)block)[3] ^= ((word32*)iv)[3];
#else
		((word32*)block)[0] = ((word32*)cipher->IV)[0] ^ ((word32*)input)[0];
		((word32*)block)[1] = ((word32*)cipher->IV)[1] ^ ((word32*)input)[1];
		((word32*)block)[2] = ((word32*)cipher->IV)[2] ^ ((word32*)input)[2];
		((word32*)block)[3] = ((word32*)cipher->IV)[3] ^ ((word32*)input)[3];
#endif
		rijndaelEncrypt(block, outBuffer, key->keySched, key->ROUNDS);
		input += 16;
		for (i = numBlocks - 1; i > 0; i--) {
#if 1 /*STRICT_ALIGN*/
			bcopy(outBuffer, block, 16);
			((word32*)block)[0] ^= ((word32*)iv)[0];
			((word32*)block)[1] ^= ((word32*)iv)[1];
			((word32*)block)[2] ^= ((word32*)iv)[2];
			((word32*)block)[3] ^= ((word32*)iv)[3];
#else
			((word32*)block)[0] = ((word32*)outBuffer)[0] ^ ((word32*)input)[0];
			((word32*)block)[1] = ((word32*)outBuffer)[1] ^ ((word32*)input)[1];
			((word32*)block)[2] = ((word32*)outBuffer)[2] ^ ((word32*)input)[2];
			((word32*)block)[3] = ((word32*)outBuffer)[3] ^ ((word32*)input)[3];
#endif
			outBuffer += 16;
			rijndaelEncrypt(block, outBuffer, key->keySched, key->ROUNDS);
			input += 16;
		}
		break;
	
	case MODE_CFB1:
#if 1 /*STRICT_ALIGN*/
		bcopy(cipher->IV, iv, 16); 
#else  /* !STRICT_ALIGN */
		*((word32*)iv[0]) = *((word32*)(cipher->IV   ));
		*((word32*)iv[1]) = *((word32*)(cipher->IV+ 4));
		*((word32*)iv[2]) = *((word32*)(cipher->IV+ 8));
		*((word32*)iv[3]) = *((word32*)(cipher->IV+12));
#endif /* ?STRICT_ALIGN */
		for (i = numBlocks; i > 0; i--) {
			for (k = 0; k < 128; k++) {
				*((word32*) block    ) = *((word32*)iv[0]);
				*((word32*)(block+ 4)) = *((word32*)iv[1]);
				*((word32*)(block+ 8)) = *((word32*)iv[2]);
				*((word32*)(block+12)) = *((word32*)iv[3]);
				rijndaelEncrypt(block, block, key->keySched, key->ROUNDS);
				outBuffer[k/8] ^= (block[0] & 0x80) >> (k & 7);
				iv[0][0] = (iv[0][0] << 1) | (iv[0][1] >> 7);
				iv[0][1] = (iv[0][1] << 1) | (iv[0][2] >> 7);
				iv[0][2] = (iv[0][2] << 1) | (iv[0][3] >> 7);
				iv[0][3] = (iv[0][3] << 1) | (iv[1][0] >> 7);
				iv[1][0] = (iv[1][0] << 1) | (iv[1][1] >> 7);
				iv[1][1] = (iv[1][1] << 1) | (iv[1][2] >> 7);
				iv[1][2] = (iv[1][2] << 1) | (iv[1][3] >> 7);
				iv[1][3] = (iv[1][3] << 1) | (iv[2][0] >> 7);
				iv[2][0] = (iv[2][0] << 1) | (iv[2][1] >> 7);
				iv[2][1] = (iv[2][1] << 1) | (iv[2][2] >> 7);
				iv[2][2] = (iv[2][2] << 1) | (iv[2][3] >> 7);
				iv[2][3] = (iv[2][3] << 1) | (iv[3][0] >> 7);
				iv[3][0] = (iv[3][0] << 1) | (iv[3][1] >> 7);
				iv[3][1] = (iv[3][1] << 1) | (iv[3][2] >> 7);
				iv[3][2] = (iv[3][2] << 1) | (iv[3][3] >> 7);
				iv[3][3] = (iv[3][3] << 1) | ((outBuffer[k/8] >> (7-(k&7))) & 1);
			}
		}
		break;
	
	default:
		return BAD_CIPHER_STATE;
	}
	
	return 128*numBlocks;
}

/**
 * Encrypt data partitioned in octets, using RFC 2040-like padding.
 *
 * @param   input           data to be encrypted (octet sequence)
 * @param   inputOctets		input length in octets (not bits)
 * @param   outBuffer       encrypted output data
 *
 * @return	length in octets (not bits) of the encrypted output buffer.
 */
int rijndael_padEncrypt(cipherInstance *cipher, keyInstance *key,
		BYTE *input, int inputOctets, BYTE *outBuffer) {
	int i, numBlocks, padLen;
	word8 block[16], *iv, *cp;

	if (cipher == NULL ||
		key == NULL ||
		key->direction == DIR_DECRYPT) {
		return BAD_CIPHER_STATE;
	}
	if (input == NULL || inputOctets <= 0) {
		return 0; /* nothing to do */
	}

	numBlocks = inputOctets/16;

	switch (cipher->mode) {
	case MODE_ECB: 
		for (i = numBlocks; i > 0; i--) {
			rijndaelEncrypt(input, outBuffer, key->keySched, key->ROUNDS);
			input += 16;
			outBuffer += 16;
		}
		padLen = 16 - (inputOctets - 16*numBlocks);
		if (padLen > 0 && padLen <= 16)
			panic("rijndael_padEncrypt(ECB)");
		bcopy(input, block, 16 - padLen);
		for (cp = block + 16 - padLen; cp < block + 16; cp++)
			*cp = padLen;
		rijndaelEncrypt(block, outBuffer, key->keySched, key->ROUNDS);
		break;

	case MODE_CBC:
		iv = cipher->IV;
		for (i = numBlocks; i > 0; i--) {
			((word32*)block)[0] = ((word32*)input)[0] ^ ((word32*)iv)[0];
			((word32*)block)[1] = ((word32*)input)[1] ^ ((word32*)iv)[1];
			((word32*)block)[2] = ((word32*)input)[2] ^ ((word32*)iv)[2];
			((word32*)block)[3] = ((word32*)input)[3] ^ ((word32*)iv)[3];
			rijndaelEncrypt(block, outBuffer, key->keySched, key->ROUNDS);
			iv = outBuffer;
			input += 16;
			outBuffer += 16;
		}
		padLen = 16 - (inputOctets - 16*numBlocks);
		if (padLen > 0 && padLen <= 16)
			panic("rijndael_padEncrypt(CBC)");
		for (i = 0; i < 16 - padLen; i++) {
			block[i] = input[i] ^ iv[i];
		}
		for (i = 16 - padLen; i < 16; i++) {
			block[i] = (BYTE)padLen ^ iv[i];
		}
		rijndaelEncrypt(block, outBuffer, key->keySched, key->ROUNDS);
		break;

	default:
		return BAD_CIPHER_STATE;
	}

	return 16*(numBlocks + 1);
}

int rijndael_blockDecrypt(cipherInstance *cipher, keyInstance *key,
		BYTE *input, int inputLen, BYTE *outBuffer) {
	int i, k, numBlocks;
	word8 block[16], iv[4][4];

	if (cipher == NULL ||
		key == NULL ||
		(cipher->mode != MODE_CFB1 && key->direction == DIR_ENCRYPT)) {
		return BAD_CIPHER_STATE;
	}
	if (input == NULL || inputLen <= 0) {
		return 0; /* nothing to do */
	}

	numBlocks = inputLen/128;

	switch (cipher->mode) {
	case MODE_ECB: 
		for (i = numBlocks; i > 0; i--) { 
			rijndaelDecrypt(input, outBuffer, key->keySched, key->ROUNDS);
			input += 16;
			outBuffer += 16;
		}
		break;
		
	case MODE_CBC:
#if 1 /*STRICT_ALIGN */
		bcopy(cipher->IV, iv, 16); 
#else
		*((word32*)iv[0]) = *((word32*)(cipher->IV   ));
		*((word32*)iv[1]) = *((word32*)(cipher->IV+ 4));
		*((word32*)iv[2]) = *((word32*)(cipher->IV+ 8));
		*((word32*)iv[3]) = *((word32*)(cipher->IV+12));
#endif
		for (i = numBlocks; i > 0; i--) {
			rijndaelDecrypt(input, block, key->keySched, key->ROUNDS);
			((word32*)block)[0] ^= *((word32*)iv[0]);
			((word32*)block)[1] ^= *((word32*)iv[1]);
			((word32*)block)[2] ^= *((word32*)iv[2]);
			((word32*)block)[3] ^= *((word32*)iv[3]);
#if 1 /*STRICT_ALIGN*/
			bcopy(input, iv, 16);
			bcopy(block, outBuffer, 16);
#else
			*((word32*)iv[0]) = ((word32*)input)[0]; ((word32*)outBuffer)[0] = ((word32*)block)[0];
			*((word32*)iv[1]) = ((word32*)input)[1]; ((word32*)outBuffer)[1] = ((word32*)block)[1];
			*((word32*)iv[2]) = ((word32*)input)[2]; ((word32*)outBuffer)[2] = ((word32*)block)[2];
			*((word32*)iv[3]) = ((word32*)input)[3]; ((word32*)outBuffer)[3] = ((word32*)block)[3];
#endif
			input += 16;
			outBuffer += 16;
		}
		break;
	
	case MODE_CFB1:
#if 1 /*STRICT_ALIGN */
		bcopy(cipher->IV, iv, 16); 
#else
		*((word32*)iv[0]) = *((word32*)(cipher->IV));
		*((word32*)iv[1]) = *((word32*)(cipher->IV+ 4));
		*((word32*)iv[2]) = *((word32*)(cipher->IV+ 8));
		*((word32*)iv[3]) = *((word32*)(cipher->IV+12));
#endif
		for (i = numBlocks; i > 0; i--) {
			for (k = 0; k < 128; k++) {
				*((word32*) block    ) = *((word32*)iv[0]);
				*((word32*)(block+ 4)) = *((word32*)iv[1]);
				*((word32*)(block+ 8)) = *((word32*)iv[2]);
				*((word32*)(block+12)) = *((word32*)iv[3]);
				rijndaelEncrypt(block, block, key->keySched, key->ROUNDS);
				iv[0][0] = (iv[0][0] << 1) | (iv[0][1] >> 7);
				iv[0][1] = (iv[0][1] << 1) | (iv[0][2] >> 7);
				iv[0][2] = (iv[0][2] << 1) | (iv[0][3] >> 7);
				iv[0][3] = (iv[0][3] << 1) | (iv[1][0] >> 7);
				iv[1][0] = (iv[1][0] << 1) | (iv[1][1] >> 7);
				iv[1][1] = (iv[1][1] << 1) | (iv[1][2] >> 7);
				iv[1][2] = (iv[1][2] << 1) | (iv[1][3] >> 7);
				iv[1][3] = (iv[1][3] << 1) | (iv[2][0] >> 7);
				iv[2][0] = (iv[2][0] << 1) | (iv[2][1] >> 7);
				iv[2][1] = (iv[2][1] << 1) | (iv[2][2] >> 7);
				iv[2][2] = (iv[2][2] << 1) | (iv[2][3] >> 7);
				iv[2][3] = (iv[2][3] << 1) | (iv[3][0] >> 7);
				iv[3][0] = (iv[3][0] << 1) | (iv[3][1] >> 7);
				iv[3][1] = (iv[3][1] << 1) | (iv[3][2] >> 7);
				iv[3][2] = (iv[3][2] << 1) | (iv[3][3] >> 7);
				iv[3][3] = (iv[3][3] << 1) | ((input[k/8] >> (7-(k&7))) & 1);
				outBuffer[k/8] ^= (block[0] & 0x80) >> (k & 7);
			}
		}
		break;

	default:
		return BAD_CIPHER_STATE;
	}
	
	return 128*numBlocks;
}

int rijndael_padDecrypt(cipherInstance *cipher, keyInstance *key,
		BYTE *input, int inputOctets, BYTE *outBuffer) {
	int i, numBlocks, padLen;
	word8 block[16];
	word32 iv[4];

	if (cipher == NULL ||
		key == NULL ||
		key->direction == DIR_ENCRYPT) {
		return BAD_CIPHER_STATE;
	}
	if (input == NULL || inputOctets <= 0) {
		return 0; /* nothing to do */
	}
	if (inputOctets % 16 != 0) {
		return BAD_DATA;
	}

	numBlocks = inputOctets/16;

	switch (cipher->mode) {
	case MODE_ECB:
		/* all blocks but last */
		for (i = numBlocks - 1; i > 0; i--) { 
			rijndaelDecrypt(input, outBuffer, key->keySched, key->ROUNDS);
			input += 16;
			outBuffer += 16;
		}
		/* last block */
		rijndaelDecrypt(input, block, key->keySched, key->ROUNDS);
		padLen = block[15];
		if (padLen >= 16) {
			return BAD_DATA;
		}
		for (i = 16 - padLen; i < 16; i++) {
			if (block[i] != padLen) {
				return BAD_DATA;
			}
		}
		bcopy(block, outBuffer, 16 - padLen);
		break;
		
	case MODE_CBC:
		bcopy(cipher->IV, iv, 16);
		/* all blocks but last */
		for (i = numBlocks - 1; i > 0; i--) {
			rijndaelDecrypt(input, block, key->keySched, key->ROUNDS);
			((word32*)block)[0] ^= iv[0];
			((word32*)block)[1] ^= iv[1];
			((word32*)block)[2] ^= iv[2];
			((word32*)block)[3] ^= iv[3];
			bcopy(input, iv, 16);
			bcopy(block, outBuffer, 16);
			input += 16;
			outBuffer += 16;
		}
		/* last block */
		rijndaelDecrypt(input, block, key->keySched, key->ROUNDS);
		((word32*)block)[0] ^= iv[0];
		((word32*)block)[1] ^= iv[1];
		((word32*)block)[2] ^= iv[2];
		((word32*)block)[3] ^= iv[3];
		padLen = block[15];
		if (padLen <= 0 || padLen > 16) {
			return BAD_DATA;
		}
		for (i = 16 - padLen; i < 16; i++) {
			if (block[i] != padLen) {
				return BAD_DATA;
			}
		}
		bcopy(block, outBuffer, 16 - padLen);
		break;
	
	default:
		return BAD_CIPHER_STATE;
	}
	
	return 16*numBlocks - padLen;
}

#ifdef INTERMEDIATE_VALUE_KAT
/**
 *	cipherUpdateRounds:
 *
 *	Encrypts/Decrypts exactly one full block a specified number of rounds.
 *	Only used in the Intermediate Value Known Answer Test.	
 *
 *	Returns:
 *		TRUE - on success
 *		BAD_CIPHER_STATE - cipher in bad state (e.g., not initialized)
 */
int rijndael_cipherUpdateRounds(cipherInstance *cipher, keyInstance *key,
		BYTE *input, int inputLen, BYTE *outBuffer, int rounds) {
	int j;
	word8 block[4][4];

	if (cipher == NULL || key == NULL) {
		return BAD_CIPHER_STATE;
	}

	for (j = 3; j >= 0; j--) {
		/* parse input stream into rectangular array */
  		*((word32*)block[j]) = *((word32*)(input+4*j));
	}

	switch (key->direction) {
	case DIR_ENCRYPT:
		rijndaelEncryptRound(block, key->keySched, key->ROUNDS, rounds);
		break;
		
	case DIR_DECRYPT:
		rijndaelDecryptRound(block, key->keySched, key->ROUNDS, rounds);
		break;
		
	default:
		return BAD_KEY_DIR;
	} 

	for (j = 3; j >= 0; j--) {
		/* parse rectangular array into output ciphertext bytes */
		*((word32*)(outBuffer+4*j)) = *((word32*)block[j]);
	}
	
	return TRUE;
}
#endif /* INTERMEDIATE_VALUE_KAT */
