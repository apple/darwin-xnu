/*	$KAME: rijndael_local.h,v 1.3 2000/10/02 17:14:27 itojun Exp $	*/
/*	$FreeBSD: src/sys/crypto/rijndael/rijndael_local.h,v 1.3.2.1 2001/07/03 11:01:36 ume Exp $	*/

/* the file should not be used from outside */
typedef u_int8_t		BYTE;
typedef u_int8_t		word8;	
typedef u_int16_t		word16;	
typedef u_int32_t		word32;

#define MAXKC		RIJNDAEL_MAXKC
#define MAXROUNDS	RIJNDAEL_MAXROUNDS
