/*
 * data_conv.c
 *
 *  Created on: 12 Oca 2021
 *      Author: toluntosun
 */

#include "crypto_conf.h"
#include "dataconv.h"

void word2mpz(mpz_t p_out, WORD *p_in, uint32_t p_precision)
{
    mpz_import(p_out, p_precision, -1, sizeof(WORD), 0, 0, (void*) p_in);
	return;
}


void mpz2word(WORD *p_out, uint32_t *p_precision, mpz_t p_in)
{
	mpz_export((void*) p_out, p_precision, -1, sizeof(WORD), 0, 0, p_in);
	return;
}
