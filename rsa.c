#include <stdlib.h>
/*
 * rsa.c
 *
 *  Created on: 10 Oca 2021
 *      Author: toluntosun
 */

#include <string.h>
#include <stdio.h>
#include <assert.h>
#include "gmp.h"
#include "crypto_conf.h"
#include "rsa.h"
#include "random.h"
#include "dataconv.h"


static int rsa_primegen(mpz_t l_mpzp, WORD *l_p, uint32_t p_precision)
{
	uint32_t l_bytepre = WORDS_TO_BYTES(p_precision);

	do
	{
		if (random_randbytes_sha256whitening((BYTE*) l_p, l_bytepre))
		{
			return -1;
		}
		word2mpz(l_mpzp, l_p, p_precision);
	}while(!mpz_millerrabin(l_mpzp, MILLER_RABIN_K));

	//TODO add bitcount check

	return 0;
}


int rsa_paramgen(rsa_pubkey *p_pubkey, rsa_privatekey *p_privkey, uint32_t p_precision)
{
	int l_ret = 0;
	WORD *l_p, *l_q;
	mpz_t l_phi, l_mpzp, l_mpzq, l_mpzd, l_mpze, l_mpzn;
	uint32_t l_bytepre = WORDS_TO_BYTES(p_precision);
	uint32_t l_pre_ctrl;


	mpz_init(l_mpzp);
	mpz_init(l_mpzq);
	mpz_init(l_mpzn);
	mpz_init(l_mpzd);
	mpz_init(l_phi);


	p_pubkey->precision = p_privkey->precision = p_precision;

	// create p
	l_p = malloc(l_bytepre >> 1);
	if (rsa_primegen(l_mpzp, l_p, p_precision >> 1))
	{
		l_ret = -1;
		goto rsa_paramgen_end;
	}
	printf("p is generated\n");
	mpz2word(p_privkey->p, &l_pre_ctrl, l_mpzp);
	if (l_pre_ctrl != (p_precision >> 1))
	{
		l_ret = -1;
		goto rsa_paramgen_end;
	}
	l_pre_ctrl = 0;

	// create q
	l_q = malloc(l_bytepre >> 1);
	if (rsa_primegen(l_mpzq, l_q, p_precision >> 1))
	{
		l_ret = -1;
		goto rsa_paramgen_end;
	}
	printf("q is generated\n");
	mpz2word(p_privkey->q, &l_pre_ctrl, l_mpzq);
	if (l_pre_ctrl != (p_precision >> 1))
	{
		l_ret = -1;
		goto rsa_paramgen_end;
	}
	l_pre_ctrl = 0;

	//compute n
	mpz_mul(l_mpzn, l_mpzp, l_mpzq);
	mpz2word(p_pubkey->n, &l_pre_ctrl, l_mpzn);
	memcpy((BYTE*) p_privkey->n, (BYTE*) p_pubkey->n, WORDS_TO_BYTES(p_precision));

	assert(l_pre_ctrl == p_precision);
	if (l_pre_ctrl != p_precision)
	{
		l_ret = -1;
		goto rsa_paramgen_end;
	}
	l_pre_ctrl = 0;


	// compute phi
	mpz_sub_ui(l_mpzp, l_mpzp, 1);
	mpz_sub_ui(l_mpzq, l_mpzq, 1);
	mpz_addmul(l_phi, l_mpzp, l_mpzq);
	printf("phi is computed\n");


	// create d
	p_pubkey->e[0] = p_privkey->e[0] = 0x11;//0x010001;
	p_pubkey->precision_pubkey = p_privkey->precision_pubkey = 1;
	mpz_init_set_ui(l_mpze, p_pubkey->e[0]); /* p = 1 */
	mpz_init(l_mpzd);
	mpz_invert(l_mpzd, l_mpze, l_phi);
	mpz_clear(l_mpze);
	printf("d is computed\n");
	mpz2word(p_privkey->d, &l_pre_ctrl, l_mpzd);
	if (l_pre_ctrl != p_precision)
	{
		l_ret = -1;
	}


rsa_paramgen_end:

	mpz_clear(l_mpzp);
	mpz_clear(l_mpzq);
	mpz_clear(l_mpzd);
	mpz_clear(l_phi);
	mpz_clear(l_mpzn);
	free(l_q);
	free(l_p);

	return l_ret;
}



int rsa_encrypt(WORD *p_out, WORD *p_in, rsa_pubkey *p_pubkey)
{
	//TODO add n, m comparison
	int l_ret = 0;
	mpz_t l_in, l_out, l_e, l_n;
	mpz_init(l_in);
	mpz_init(l_out);
	mpz_init(l_e);
	mpz_init(l_n);
	uint32_t l_pre_ctrl;

	word2mpz(l_in, p_in, p_pubkey->precision);
	word2mpz(l_e, p_pubkey->e, p_pubkey->precision_pubkey);
	word2mpz(l_n, p_pubkey->n, p_pubkey->precision);

	mpz_powm(l_out, l_in, l_e, l_n);
	mpz2word(p_out, &l_pre_ctrl, l_out);


	mpz_clear(l_in);
	mpz_clear(l_out);
	mpz_clear(l_e);
	mpz_clear(l_n);

	return l_ret;
}

int rsa_decrypt(WORD *p_out, WORD *p_in, rsa_privatekey *p_privkey)
{
	//TODO add n, m comparison
	int l_ret = 0;
	mpz_t l_in, l_out, l_d, l_n;
	mpz_init(l_in);
	mpz_init(l_out);
	mpz_init(l_d);
	mpz_init(l_n);
	uint32_t l_pre_ctrl;

	word2mpz(l_in, p_in, p_privkey->precision);
	word2mpz(l_d, p_privkey->d, p_privkey->precision);
	word2mpz(l_n, p_privkey->n, p_privkey->precision);

	mpz_powm_sec(l_out, l_in, l_d, l_n);
	mpz2word(p_out, &l_pre_ctrl, l_out);


	mpz_clear(l_in);
	mpz_clear(l_out);
	mpz_clear(l_d);
	mpz_clear(l_n);

	return l_ret;
}


int rsa_test(const uint32_t p_testnum, const uint32_t p_rsa_precision)
{
	int i;
	rsa_pubkey l_pubkey;
	rsa_privatekey l_privkey;
	WORD l_m[RSA_MAX_PRECISION], l_c[RSA_MAX_PRECISION], l_m_[RSA_MAX_PRECISION];
	const uint32_t l_precision = p_rsa_precision >> 5;


	for (i = 0; i < p_testnum; i++)
	{
		printf("RSA-%d - Test %d\n", p_rsa_precision, i);
		if (rsa_paramgen(&l_pubkey, &l_privkey, l_precision) == 0)
		{
			printf("Key generation successful\n");
		}

		if (random_randbytes((BYTE*) l_m, WORDS_TO_BYTES(l_pubkey.precision)))
		{
			return -3;
		}
		else
		{
			l_m[l_pubkey.precision - 1] &= 0x7FFFFFFF; // remove first bit, TODO add comparison
			if (rsa_encrypt(l_c, l_m, &l_pubkey))
			{
				return -1;
			}
			else
			{
				printf("Encryption Successful %d\n", i);
			}
			if (rsa_decrypt(l_m_, l_c, &l_privkey))
			{
				return -1;
			}
			else
			{
				printf("Decryption Successful %d\n", i);
			}
			if (memcmp((BYTE*) l_m_,(BYTE*) l_m, WORDS_TO_BYTES(l_pubkey.precision)))
			{
				return -2;
			}
			else
			{
				printf("Result Correct %d\n", i);
			}
		}
		printf("\n\n");

	}

	return 0;
}
