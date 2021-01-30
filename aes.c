/*
 * aes.c
 *
 *  Created on: 12 Oca 2021
 *      Author: toluntosun
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wmmintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>
#include "crypto_conf.h"
#include "aes.h"
#include "random.h"

/*
 * KEY_256_ASSIST_1, KEY_256_ASSIST_2, AES_256_Key_Expansion, AES_CTR_encrypt(with slight modifications)
 * https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf
 */

static inline void KEY_256_ASSIST_1(__m128i* temp1, __m128i * temp2)
{
	__m128i temp4;
	*temp2 = _mm_shuffle_epi32(*temp2, 0xff);
	temp4 = _mm_slli_si128 (*temp1, 0x4);
	*temp1 = _mm_xor_si128 (*temp1, temp4);
	temp4 = _mm_slli_si128 (temp4, 0x4);
	*temp1 = _mm_xor_si128 (*temp1, temp4);
	temp4 = _mm_slli_si128 (temp4, 0x4);
	*temp1 = _mm_xor_si128 (*temp1, temp4);
	*temp1 = _mm_xor_si128 (*temp1, *temp2);
}

static inline void KEY_256_ASSIST_2(__m128i* temp1, __m128i * temp3)
{
	__m128i temp2,temp4;
	temp4 = _mm_aeskeygenassist_si128 (*temp1, 0x0);
	temp2 = _mm_shuffle_epi32(temp4, 0xaa);
	temp4 = _mm_slli_si128 (*temp3, 0x4);
	*temp3 = _mm_xor_si128 (*temp3, temp4);
	temp4 = _mm_slli_si128 (temp4, 0x4);
	*temp3 = _mm_xor_si128 (*temp3, temp4);
	temp4 = _mm_slli_si128 (temp4, 0x4);
	*temp3 = _mm_xor_si128 (*temp3, temp4);
	*temp3 = _mm_xor_si128 (*temp3, temp2);
}

static void AES_256_Key_Expansion(const unsigned char *userkey,
		unsigned char *key) {
	__m128i temp1, temp2, temp3;
	__m128i *Key_Schedule = (__m128i *) key;
	temp1 = _mm_loadu_si128((__m128i *) userkey);
	temp3 = _mm_loadu_si128((__m128i *) (userkey + 16));
	Key_Schedule[0] = temp1;
	Key_Schedule[1] = temp3;
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x01);
	KEY_256_ASSIST_1(&temp1, &temp2);
	Key_Schedule[2] = temp1;
	KEY_256_ASSIST_2(&temp1, &temp3);
	Key_Schedule[3] = temp3;
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x02);
	KEY_256_ASSIST_1(&temp1, &temp2);
	Key_Schedule[4] = temp1;
	KEY_256_ASSIST_2(&temp1, &temp3);
	Key_Schedule[5] = temp3;
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x04);
	KEY_256_ASSIST_1(&temp1, &temp2);
	Key_Schedule[6] = temp1;
	KEY_256_ASSIST_2(&temp1, &temp3);
	Key_Schedule[7] = temp3;
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x08);
	KEY_256_ASSIST_1(&temp1, &temp2);
	Key_Schedule[8] = temp1;
	KEY_256_ASSIST_2(&temp1, &temp3);
	Key_Schedule[9] = temp3;
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x10);
	KEY_256_ASSIST_1(&temp1, &temp2);
	Key_Schedule[10] = temp1;
	KEY_256_ASSIST_2(&temp1, &temp3);
	Key_Schedule[11] = temp3;
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x20);
	KEY_256_ASSIST_1(&temp1, &temp2);
	Key_Schedule[12] = temp1;
	KEY_256_ASSIST_2(&temp1, &temp3);
	Key_Schedule[13] = temp3;
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x40);
	KEY_256_ASSIST_1(&temp1, &temp2);
	Key_Schedule[14] = temp1;
}

void AES_CTR_encrypt(const unsigned char *in, unsigned char *out, const unsigned char nonce[16],
		unsigned long length, const unsigned char *key, int number_of_rounds) {
	__m128i ctr_block, tmp, ONE, BSWAP_EPI64;
	int i, j;
	if (length % 16)
		length = length / 16 + 1;
	else
		length /= 16;
	ONE = _mm_set_epi32(0, 1, 0, 0);
	BSWAP_EPI64 = _mm_setr_epi8(7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10,
			9, 8);
	ctr_block = _mm_insert_epi32(ctr_block, 0, 0);
	ctr_block = _mm_insert_epi32(ctr_block, 0, 1);
	ctr_block = _mm_insert_epi32(ctr_block, 0, 2);
	ctr_block = _mm_insert_epi32(ctr_block, 0, 3);

	ctr_block = _mm_insert_epi8(ctr_block, nonce[0], 0);
	ctr_block = _mm_insert_epi8(ctr_block, nonce[1], 1);
	ctr_block = _mm_insert_epi8(ctr_block, nonce[2], 2);
	ctr_block = _mm_insert_epi8(ctr_block, nonce[3], 3);
	ctr_block = _mm_insert_epi8(ctr_block, nonce[4], 4);
	ctr_block = _mm_insert_epi8(ctr_block, nonce[5], 5);
	ctr_block = _mm_insert_epi8(ctr_block, nonce[6], 6);
	ctr_block = _mm_insert_epi8(ctr_block, nonce[7], 7);
	ctr_block = _mm_insert_epi8(ctr_block, nonce[8], 8);
	ctr_block = _mm_insert_epi8(ctr_block, nonce[9], 9);
	ctr_block = _mm_insert_epi8(ctr_block, nonce[10], 10);
	ctr_block = _mm_insert_epi8(ctr_block, nonce[11], 11);
	ctr_block = _mm_insert_epi8(ctr_block, nonce[12], 12);
	ctr_block = _mm_insert_epi8(ctr_block, nonce[13], 13);
	ctr_block = _mm_insert_epi8(ctr_block, nonce[14], 14);
	ctr_block = _mm_insert_epi8(ctr_block, nonce[15], 15);

	for (i = 0; i < length; i++) {
		tmp = ctr_block;
		tmp = _mm_xor_si128(tmp, ((__m128i *) key)[0]);
		for (j = 1; j < number_of_rounds; j++) {
			tmp = _mm_aesenc_si128(tmp, ((__m128i *) key)[j]);
		};
		tmp = _mm_aesenclast_si128(tmp, ((__m128i *) key)[j]);
		tmp = _mm_xor_si128(tmp, _mm_loadu_si128(&((__m128i *) in)[i]));
		_mm_storeu_si128(&((__m128i *) out)[i], tmp);
		ctr_block = _mm_shuffle_epi8(ctr_block, BSWAP_EPI64);
		ctr_block = _mm_add_epi64(ctr_block, ONE);
		ctr_block = _mm_shuffle_epi8(ctr_block, BSWAP_EPI64);
	}
	_mm_storeu_si128(((__m128i *) nonce), ctr_block);
}

int aes_ctr_init(aes_ctx *p_ctx, BYTE *p_key, uint32_t p_keylen, BYTE *p_nonce) {
	int l_ret = 0;
	uint32_t l_key[12];
	uint32_t l_round_keys[BYTES_TO_WORDS((AES_MAX_ROUNDS + 2) * AES_BLOCKSIZE)];

	// workaround for alignment to 128-bit
	unsigned char *l_key_ptr;
	l_key_ptr = (unsigned char*) (((uint32_t)(l_key + 4)) & 0xFFFFFFF0);
	unsigned char *l_round_keys_ptr;
	l_round_keys_ptr = (unsigned char*) (((uint32_t)(l_round_keys + 4)) & 0xFFFFFFF0);

	memcpy((BYTE*) l_key_ptr, p_key, p_keylen);
	memcpy((BYTE*) p_ctx->nonce, p_nonce, 8);
	memset((BYTE*) p_ctx->nonce + 8, 0x00, AES_BLOCKSIZE - 8);
	if (p_keylen == 32)
	{
		p_ctx->key_len = p_keylen;
		AES_256_Key_Expansion((unsigned char*) l_key_ptr,
				(unsigned char*) l_round_keys_ptr);
		memcpy((BYTE*) p_ctx->round_keys, (BYTE*) l_round_keys_ptr,
				(AES_MAX_ROUNDS + 1) * AES_BLOCKSIZE);
		l_ret = 0;
	}
	else
	{
		l_ret = -1;
	}

	memset((BYTE*) l_key_ptr, 0x00, p_keylen);
	memset((BYTE*) l_round_keys_ptr, 0x00, (AES_MAX_ROUNDS + 1) * AES_BLOCKSIZE);
	return l_ret;
}


int aes_ctr_update(BYTE *p_out, BYTE *p_in, uint32_t p_len, aes_ctx *p_ctx) {
	int l_ret = 0;
	uint32_t l_num_rounds;
	uint32_t l_round_keys[BYTES_TO_WORDS((AES_MAX_ROUNDS + 2) * AES_BLOCKSIZE)];
	unsigned char *l_round_keys_ptr;
	l_round_keys_ptr = (unsigned char*) (((uint32_t)(l_round_keys + 4)) & 0xFFFFFFF0);
	memcpy((BYTE*) l_round_keys_ptr, (BYTE*) p_ctx->round_keys, (AES_MAX_ROUNDS + 1) * AES_BLOCKSIZE);

	if (p_ctx->key_len == 32)
	{
		l_num_rounds = 14;
	}
	else
	{
		l_ret = -1;
		goto aes_ctr_update_end;
	}

	AES_CTR_encrypt(p_in, p_out, p_ctx->nonce, p_len, l_round_keys_ptr, l_num_rounds);

aes_ctr_update_end:
	memset((BYTE*) l_round_keys_ptr, 0x00, (AES_MAX_ROUNDS + 1) * AES_BLOCKSIZE);
	return l_ret;
}


int aes_ctr_test(const uint32_t p_testnum) {
	int i, k, l_aeskeylen;
	aes_ctx l_ctx_enc, l_ctx_dec;
	BYTE l_key[64];
	const uint32_t l_chunksize = 64;
	const uint32_t l_chunkiter = 4;
	const uint32_t l_testsize = l_chunksize * l_chunkiter;
	BYTE l_pt[l_testsize];
	BYTE l_ct[l_testsize];
	BYTE l_pt_[l_testsize];
	BYTE l_nonce[AES_BLOCKSIZE];

	for (l_aeskeylen = 32; l_aeskeylen <= 32; l_aeskeylen += 16)
		for (i = 0; i < p_testnum; i++) {
			printf("AES%d - Test %d\n", BYTES_TO_BITS(l_aeskeylen), i);

			if (random_randbytes((BYTE*) l_key, l_aeskeylen)) {
				return -3;
			} else {
				random_randbytes((BYTE*) l_pt, l_testsize);
				random_randbytes((BYTE*) l_nonce, 8);
				if (aes_ctr_init(&l_ctx_enc, l_key, l_aeskeylen, l_nonce)) {
					return -1;
				} else {
					printf("AES%d Enc Initialization Successful %d\n", BYTES_TO_BITS(l_aeskeylen), i);
				}
				if (aes_ctr_init(&l_ctx_dec, l_key, l_aeskeylen, l_nonce)) {
					return -1;
				} else {
					printf("AES%d Dec Initialization Successful %d\n", BYTES_TO_BITS(l_aeskeylen), i);
				}
				for (k = 0; k < l_chunkiter; k++)
				{
					if (aes_ctr_update(l_ct + k * l_chunksize, l_pt + k * l_chunksize, l_chunksize, &l_ctx_enc)) {
						return -1;
					} else {
						printf("AES%d CTR Encryption (%d/%d-%d) Successful\n", BYTES_TO_BITS(l_aeskeylen), k + 1, l_chunkiter, i + 1);
					}
					if (aes_ctr_update(l_pt_ + k * l_chunksize, l_ct + k * l_chunksize, l_chunksize, &l_ctx_dec)) {
						return -1;
					} else {
						printf("AES%d CTR Decryption (%d/%d-%d) Successful\n", BYTES_TO_BITS(l_aeskeylen), k + 1, l_chunkiter, i + 1);
					}
					if (memcmp((BYTE*) l_pt_,(BYTE*) l_pt, l_chunksize))
					{
						return -2;
					}
					else
					{
						printf("Result Correct (%d/%d-%d)\n\n", k + 1, l_chunkiter, i + 1);
					}
				}

			}
			printf("\n\n");

		}

	return 0;
}

