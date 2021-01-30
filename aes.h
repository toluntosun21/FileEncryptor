/*
 * aes.h
 *
 *  Created on: 12 Oca 2021
 *      Author: toluntosun
 */

#ifndef AES_H_
#define AES_H_

#define AES_MAX_ROUNDS 14
#define AES_BLOCKSIZE 16

typedef struct {
	BYTE round_keys[(AES_MAX_ROUNDS + 1) * AES_BLOCKSIZE];
	BYTE nonce[AES_BLOCKSIZE]; // or iv
	uint32_t key_len;
} aes_ctx;

int aes_ctr_init(aes_ctx *p_ctx, BYTE *p_key, uint32_t p_keylen, BYTE *p_nonce);

int aes_ctr_update(BYTE *p_out, BYTE *p_in, uint32_t p_len, aes_ctx *p_ctx);

int aes_ctr_test(const uint32_t p_testnum);


#endif /* AES_H_ */
