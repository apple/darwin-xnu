/*
 * Copyright (c) 2019 Apple Inc.
 * All rights reserved.
 */

#include <sys/systm.h>
#include <sys/errno.h>
#include <corecrypto/cchmac.h>
#include <net/content_filter.h>
#include <net/content_filter_crypto.h>

extern int cfil_log_level;

#define CFIL_CRYPTO_LOG(level, fmt, ...) \
do { \
    if (cfil_log_level >= level) \
	printf("%s:%d " fmt "\n",\
	    __FUNCTION__, __LINE__, ##__VA_ARGS__); \
} while (0)

#define CFIL_CRYPTO_LOG_4BYTES(name) \
    CFIL_CRYPTO_LOG(LOG_DEBUG, \
	            "%s \t%s: %hhX %hhX %hhX %hhX", \
	            prefix, name, ptr[0], ptr[1], ptr[2], ptr[3])

#define CFIL_CRYPTO_LOG_8BYTES(name) \
    CFIL_CRYPTO_LOG(LOG_DEBUG, \
	            "%s \t%s: %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX", \
	            prefix, name, ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5], ptr[6], ptr[7])

#define CFIL_CRYPTO_LOG_16BYTES(name) \
    CFIL_CRYPTO_LOG(LOG_DEBUG, \
	        "%s \t%s: %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX", \
	        prefix, name, ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5], ptr[6], ptr[7], ptr[8], ptr[9], ptr[10], ptr[11], ptr[12], ptr[13], ptr[14], ptr[15])

#define CFIL_CRYPTO_LOG_28BYTES(name) \
    CFIL_CRYPTO_LOG(LOG_DEBUG, \
	            "%s \t%s: %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX", \
	            prefix, name, ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5], ptr[6], ptr[7], ptr[8], ptr[9], ptr[10], ptr[11], ptr[12], ptr[13], ptr[14], ptr[15], ptr[16], ptr[17], ptr[18], ptr[19], ptr[20], ptr[21], ptr[22], ptr[23], ptr[24], ptr[25], ptr[26], ptr[27])

#define CFIL_CRYPTO_LOG_32BYTES(name, prefix) \
    CFIL_CRYPTO_LOG(LOG_DEBUG, \
	            "%s \t%s: %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX", \
	            prefix, name, ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5], ptr[6], ptr[7], ptr[8], ptr[9], ptr[10], ptr[11], ptr[12], ptr[13], ptr[14], ptr[15], ptr[16], ptr[17], ptr[18], ptr[19], ptr[20], ptr[21], ptr[22], ptr[23], ptr[24], ptr[25], ptr[26], ptr[27], ptr[28], ptr[29], ptr[30], ptr[31])

static void
cfil_crypto_print_data(cfil_crypto_data_t data, const char *prefix)
{
	u_int8_t *ptr = NULL;
	CFIL_CRYPTO_LOG(LOG_DEBUG, "%s NE Filter crypto data:", prefix);

	ptr = (u_int8_t *)&data->flow_id;
	CFIL_CRYPTO_LOG_16BYTES("flow_id");

	ptr = (u_int8_t *)&data->sock_id;
	CFIL_CRYPTO_LOG_8BYTES("sock_id");

	ptr = (u_int8_t *)&data->direction;
	CFIL_CRYPTO_LOG_4BYTES("direction");

	ptr = (u_int8_t *)&data->remote;
	CFIL_CRYPTO_LOG_28BYTES("remote");
	ptr = (u_int8_t *)&data->local;
	CFIL_CRYPTO_LOG_28BYTES("local");

	ptr = (u_int8_t *)&data->socketProtocol;
	CFIL_CRYPTO_LOG_4BYTES("socketProtocol");

	ptr = (u_int8_t *)&data->pid;
	CFIL_CRYPTO_LOG_4BYTES("pid");

	ptr = (u_int8_t *)&data->effective_pid;
	CFIL_CRYPTO_LOG_4BYTES("effective_pid");

	ptr = (u_int8_t *)&data->uuid;
	CFIL_CRYPTO_LOG_16BYTES("uuid");
	ptr = (u_int8_t *)&data->effective_uuid;
	CFIL_CRYPTO_LOG_16BYTES("effective_uuid");

	ptr = (u_int8_t *)&data->byte_count_in;
	CFIL_CRYPTO_LOG_8BYTES("byte_count_in");

	ptr = (u_int8_t *)&data->byte_count_out;
	CFIL_CRYPTO_LOG_8BYTES("byte_count_out");
}

cfil_crypto_state_t
cfil_crypto_init_client(cfil_crypto_key client_key)
{
	if (client_key == NULL) {
		return NULL;
	}

	struct cfil_crypto_state *state;
	MALLOC(state, struct cfil_crypto_state *, sizeof(struct cfil_crypto_state),
	    M_TEMP, M_WAITOK | M_ZERO);
	if (state == NULL) {
		return NULL;
	}

	memcpy(state->key, client_key, sizeof(cfil_crypto_key));
	state->digest_info = ccsha256_di();

	CFIL_CRYPTO_LOG(LOG_DEBUG, "Inited client key");
	return state;
}

void
cfil_crypto_cleanup_state(cfil_crypto_state_t state)
{
	if (state != NULL) {
		FREE(state, M_TEMP);
	}
}

static void
cfil_crypto_update_context(const struct ccdigest_info *di,
    cchmac_ctx_t ctx,
    cfil_crypto_data_t data)
{
	const uint8_t context[32] = {[0 ... 31] = 0x20}; // 0x20 repeated 32 times
	const char *context_string = "NEFilterCrypto";
	uint8_t separator = 0;
	cchmac_update(di, ctx, sizeof(context), context);
	cchmac_update(di, ctx, strlen(context_string), context_string);
	cchmac_update(di, ctx, sizeof(separator), &separator);
	cchmac_update(di, ctx, sizeof(struct cfil_crypto_data), data);
}

int
cfil_crypto_sign_data(cfil_crypto_state_t state, cfil_crypto_data_t data,
    cfil_crypto_signature signature, u_int32_t *signature_length)
{
	u_int8_t *ptr = NULL;

	if (state->digest_info == NULL) {
		return EINVAL;
	}

	if (data == NULL ||
	    signature == NULL ||
	    signature_length == NULL) {
		return EINVAL;
	}

	size_t required_tag_length = state->digest_info->output_size;
	if (*signature_length < required_tag_length) {
		return ERANGE;
	}

	*signature_length = (u_int32_t)required_tag_length;

	cchmac_ctx_decl(state->digest_info->state_size,
	    state->digest_info->block_size, ctx);
	cchmac_init(state->digest_info, ctx,
	    sizeof(state->key),
	    state->key);
	cfil_crypto_update_context(state->digest_info, ctx, data);
	cchmac_final(state->digest_info, ctx, signature);

	if (cfil_log_level >= LOG_DEBUG) {
		cfil_crypto_print_data(data, "SIGN");
		CFIL_CRYPTO_LOG(LOG_DEBUG, "Signed data: datalen %lu", sizeof(struct cfil_crypto_data));
		ptr = (u_int8_t *)signature;
		CFIL_CRYPTO_LOG_32BYTES("Signature", "SIGN");
	}

	return 0;
}
