/*	$FreeBSD: src/sys/crypto/rijndael/rijndael-alg-fst.h,v 1.2.2.1 2001/07/03 11:01:35 ume Exp $	*/
/*	$KAME: rijndael-alg-fst.h,v 1.4 2000/10/02 17:14:26 itojun Exp $	*/

/*
 * rijndael-alg-fst.h   v2.3   April '2000
 *
 * Optimised ANSI C code
 *
 * #define INTERMEDIATE_VALUE_KAT to generate the Intermediate Value Known Answer Test.
 */

#ifndef __RIJNDAEL_ALG_FST_H
#define __RIJNDAEL_ALG_FST_H

#define RIJNDAEL_MAXKC			(256/32)
#define RIJNDAEL_MAXROUNDS		14

int rijndaelKeySched(u_int8_t k[RIJNDAEL_MAXKC][4], u_int8_t rk[RIJNDAEL_MAXROUNDS+1][4][4], int ROUNDS);

int rijndaelKeyEncToDec(u_int8_t W[RIJNDAEL_MAXROUNDS+1][4][4], int ROUNDS);

int rijndaelEncrypt(u_int8_t a[16], u_int8_t b[16], u_int8_t rk[RIJNDAEL_MAXROUNDS+1][4][4], int ROUNDS);

#ifdef INTERMEDIATE_VALUE_KAT
int rijndaelEncryptRound(u_int8_t a[4][4], u_int8_t rk[RIJNDAEL_MAXROUNDS+1][4][4], int ROUNDS, int rounds);
#endif /* INTERMEDIATE_VALUE_KAT */

int rijndaelDecrypt(u_int8_t a[16], u_int8_t b[16], u_int8_t rk[RIJNDAEL_MAXROUNDS+1][4][4], int ROUNDS);

#ifdef INTERMEDIATE_VALUE_KAT
int rijndaelDecryptRound(u_int8_t a[4][4], u_int8_t rk[RIJNDAEL_MAXROUNDS+1][4][4], int ROUNDS, int rounds);
#endif /* INTERMEDIATE_VALUE_KAT */

#endif /* __RIJNDAEL_ALG_FST_H */
