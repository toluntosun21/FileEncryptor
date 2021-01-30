/*
 * random.c
 *
 *  Created on: 10 Oca 2021
 *      Author: toluntosun
 */

#include <stdint.h>
#include <string.h>
#include "crypto_conf.h"
#include "random.h"
#include "sha256.h"


#define WHITENING_INPUT_BLOCK_SIZE 128


int random_randbytes(BYTE *p_out, uint32_t p_len) {

	uint32_t l_successes = 0;
	uint32_t l_temp = 0;
	int i;

	for(i = 0; i < p_len; i++)
	{
		__asm volatile(
			"rdrand %0 ;\n"                    // Generate random value
			"adc $0, %1 ;\n"                   // Check if successul
			: "=r" (l_temp), "=r" (l_successes));

		p_out[i] = l_temp;
	}

	return l_successes != p_len;
}


int random_randbytes_sha256whitening(BYTE *p_out, uint32_t p_len) {

	int i, l_ret, l_iter;
	BYTE l_temp_in[WHITENING_INPUT_BLOCK_SIZE];
	BYTE l_temp_digest[SHA256_HASH_SIZE];

	l_iter = p_len / SHA256_HASH_SIZE + ((p_len % SHA256_HASH_SIZE) != 0);

	for(i = 0; i < l_iter; i++)
	{
		l_ret = random_randbytes(l_temp_in, WHITENING_INPUT_BLOCK_SIZE);
		if (l_ret)
		{
			return l_ret;
		}
		else
		{
			sha256(l_temp_digest, l_temp_in, WHITENING_INPUT_BLOCK_SIZE);
		}

		if ((i < (l_iter - 1)) || ((p_len % SHA256_HASH_SIZE) == 0))
		{
			memcpy(p_out + (i * SHA256_HASH_SIZE), l_temp_digest, SHA256_HASH_SIZE);
		}
		else
		{
			memcpy(p_out + (i * SHA256_HASH_SIZE), l_temp_digest, p_len % SHA256_HASH_SIZE);
		}
	}

	return 0;
}
