/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
#include "../inc/crypto_wrapper.h"

#include "../inc/byte_array.h"
#include "../inc/error.h"

#ifdef OSCORE_WITH_TINYCRYPT_AES_128

#include <string.h>
#include <tinycrypt/aes.h>
#include <tinycrypt/ccm_mode.h>

#elif defined(OSCORE_WITH_TINYDTLS_AES_128)
#include "crypto.h"

#endif

#if defined(OSCORE_WITH_TINYCRYPT_SHA_256)
#include <tinycrypt/constants.h>
#include <tinycrypt/hmac.h>

#define try_tc(e)                                                              \
	do {                                                                   \
		int res = (e);                                                 \
		if (res != TC_CRYPTO_SUCCESS) {                                \
			return OscoreTinyCryptError;                           \
		}                                                              \
	} while (0)

#define SALT_SIZE 32

#endif /* OSCORE_WITH_TINYCRYPT_SHA_256 */

OscoreError __attribute__((weak))
aes_ccm_16_64_128(enum aes_operation op, struct byte_array *in,
		  struct byte_array *out, struct byte_array *key,
		  struct byte_array *nonce, struct byte_array *aad,
		  struct byte_array *tag)
{
#if defined(OSCORE_WITH_TINYCRYPT_AES_128)
	int result = TC_CRYPTO_SUCCESS;

	struct tc_ccm_mode_struct c;
	struct tc_aes_key_sched_struct sched;
	tc_aes128_set_encrypt_key(&sched, key->ptr);

	result = tc_ccm_config(&c, &sched, nonce->ptr, nonce->len, 8);
	if (result == 0) {
		return OscoreTinyCryptError;
	}

	if (op == DECRYPT) {
		result = tc_ccm_decryption_verification(out->ptr, out->len,
							aad->ptr, aad->len,
							in->ptr, in->len, &c);

		if (result == 0) {
			return OscoreAuthenticationError;
		}

	} else {
		result = tc_ccm_generation_encryption(out->ptr, out->len,
							  aad->ptr, aad->len,
							  in->ptr, in->len, &c);

		if (result == 0) {
			return OscoreTinyCryptError;
		}
	}

#elif defined(OSCORE_WITH_TINYDTLS_AES_128)

	const dtls_ccm_params_t params = {
		.nonce = nonce->ptr,
		.tag_length = 8,	/* M value (in bytes) from table 10 - RFC 8152 */
		.l = 2				/* L value (in bytes) from table 10 - RFC 8152 */
	};

	int result = 0;

	if (op == DECRYPT) {
		result = dtls_decrypt_params(&params, in->ptr, in->len, out->ptr, key->ptr, key->len,
										aad->ptr, aad->len);
	}
	else {
		result = dtls_encrypt_params(&params, in->ptr, in->len, out->ptr, key->ptr, key->len,
										aad->ptr, aad->len);
		if (result < 0) {
			return OscoreAuthenticationError;
		}
	}

#endif

	return OscoreNoError;
};

OscoreError __attribute__((weak))
hkdf_sha_256(struct byte_array *master_secret, struct byte_array *master_salt,
		 struct byte_array *info, struct byte_array *out)
{
#if defined(OSCORE_WITH_TINYCRYPT_SHA_256)

	uint8_t default_salt[SALT_SIZE] = { 0 };
	struct byte_array salt;

	// "Note that [RFC5869] specifies that if the salt is not provided, it is
	// set to a string of zeros.  For implementation purposes, not providing
	// the salt is the same as setting the salt to the empty byte string.
	// OSCORE sets the salt default value to empty byte string, which is
	// converted to a string of zeroes (see Section 2.2 of [RFC5869])".
	if (master_salt->ptr == NULL || master_salt->len == 0) {
		salt.ptr = default_salt;
		salt.len = sizeof(default_salt);
	} else {
		salt = *master_salt;
	}

	struct tc_hmac_state_struct h;

	// extract
	uint8_t prk[32];
	memset(&h, 0x00, sizeof(h));
	try_tc(tc_hmac_set_key(&h, salt.ptr, salt.len));
	try_tc(tc_hmac_init(&h));
	try_tc(tc_hmac_update(&h, master_secret->ptr, master_secret->len));
	try_tc(tc_hmac_final(prk, TC_SHA256_DIGEST_SIZE, &h));

	// expand
	// "N = ceil(L/HashLen)"
	size_t iterations = (out->len + 31) / 32;
	// "L length of output keying material in octets (<= 255*HashLen)"
	if (iterations > 255) {
		return OscoreOutTooLong;
	}

	uint8_t t[32] = { 0 };
	for (uint8_t i = 1; i <= iterations; i++) {
		memset(&h, 0x00, sizeof(h));
		try_tc(tc_hmac_set_key(&h, prk, 32));
		try_tc(tc_hmac_init(&h));
		if (i > 1) {
			try_tc(tc_hmac_update(&h, t, 32));
		}
		try_tc(tc_hmac_update(&h, info->ptr, info->len));
		try_tc(tc_hmac_update(&h, &i, 1));
		try_tc(tc_hmac_final(t, TC_SHA256_DIGEST_SIZE, &h));
		if (out->len < i * 32) {
			memcpy(&out->ptr[(i - 1) * 32], t, out->len % 32);
		} else {
			memcpy(&out->ptr[(i - 1) * 32], t, 32);
		}
	}

	return OscoreNoError;

#endif /* OSCORE_WITH_TINYCRYPT_SHA_256 */
};
