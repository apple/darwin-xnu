#define BSWAP_32(x) \
	((x & 0x000000ff) << 24) | \
	((x & 0x0000ff00) <<  8) | \
	((x & 0x00ff0000) >>  8) | \
	((x & 0xff000000) >> 24)

#define COMMPAGE_SIGS_BEGIN \
.const_data				; \
.align 2				; \
.private_extern _commpage_sigs_begin	; \
_commpage_sigs_begin:

#define COMMPAGE_SIGS_DONE \
.private_extern _commpage_sigs_end	; \
_commpage_sigs_end:			; \

#define COMMPAGE_SIG_START(x) \
.private_extern _commpage_sig ## x 	; \
_commpage_sig ## x ## :			; \
	.long BSWAP_32(0x14400000)	; \
	.long BSWAP_32(0x00000001)	; \
	.asciz # x 			; \
	.align 2			; \
	.long BSWAP_32(0x14400000) 

#define COMMPAGE_SIG_END(x) \
	.long BSWAP_32(0x4e800020)	; \
	.long BSWAP_32(0x14400000)	; \
	.long BSWAP_32(0x00000000)	; \
	.asciz # x			; \
	.align 2			; \
	.long BSWAP_32(0x14400000)

#define ARG(n) \
	((((n * 2) + 6) << 20) + 4)

#define COMMPAGE_SIG_ARG(n) \
	.long BSWAP_32(0x14400001)	; \
	.long BSWAP_32(ARG(n))		; \
	.long BSWAP_32(0x14400001)

#define COMMPAGE_SIG_CALL(x, n) \
	.long BSWAP_32(0x14400002)	; \
	.long BSWAP_32(n)		; \
	.long BSWAP_32(0x00000000)	; \
	.asciz # x			; \
	.align 2			; \
	.long BSWAP_32(0x14400002)

#define COMMPAGE_SIG_CALL_VOID(x) \
	COMMPAGE_SIG_CALL(x, 0)

#define COMMPAGE_SIG_CALL_RET0(x) \
	COMMPAGE_SIG_CALL(x, ARG(0))

#define COMMPAGE_SIG_CALL_RET1(x) \
	COMMPAGE_SIG_CALL(x, ARG(1))
