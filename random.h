/*
 * random.h
 *
 *  Created on: 10 Oca 2021
 *      Author: toluntosun
 */

#ifndef RANDOM_H
#define RANDOM_H

#include "crypto_conf.h"

int random_randbytes(BYTE *p_out, uint32_t p_len);


int random_randbytes_sha256whitening(BYTE *p_out, uint32_t p_len);


#endif /* RANDOM_H */
