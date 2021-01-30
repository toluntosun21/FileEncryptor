/*
 * data_conv.h
 *
 *  Created on: 12 Oca 2021
 *      Author: toluntosun
 */

#ifndef DATA_CONV_H
#define DATA_CONV_H

#include "gmp.h"
#include "crypto_conf.h"

void word2mpz(mpz_t p_out, WORD *p_in, uint32_t p_precision);

void mpz2word(WORD *p_out, uint32_t *p_precision, mpz_t p_in);

#endif /* DATA_CONV_H */
