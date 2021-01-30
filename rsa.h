/*
 * rsa.h
 *
 *  Created on: 10 Oca 2021
 *      Author: toluntosun
 */

#ifndef RSA_H_
#define RSA_H_

#include "gmp.h"
#include "crypto_conf.h"

typedef struct {
	uint32_t precision;
	uint32_t precision_pubkey;
	WORD n[RSA_MAX_PRECISION];
	WORD e[RSA_MAX_PRE_PUBKEY];

} rsa_pubkey;

typedef struct {
	uint32_t precision;
	uint32_t precision_pubkey;
	WORD n[RSA_MAX_PRECISION];
	WORD p[RSA_MAX_PRECISION / 2];
	WORD q[RSA_MAX_PRECISION / 2];
	WORD e[RSA_MAX_PRE_PUBKEY];
	WORD d[RSA_MAX_PRECISION];

} rsa_privatekey;


int rsa_paramgen(rsa_pubkey *p_pubkey, rsa_privatekey *p_privkey, uint32_t p_precision);

int rsa_encrypt(WORD *p_out, WORD *p_in, rsa_pubkey *p_pubkey);

int rsa_decrypt(WORD *p_out, WORD *p_in, rsa_privatekey *p_privkey);

int rsa_test(const uint32_t p_testnum, const uint32_t p_rsa_precision);

#endif /* RSA_H_ */
