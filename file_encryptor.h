/*
 * file_encryptor.h
 *
 *  Created on: 20 Oca 2021
 *      Author: toluntosun
 */

#ifndef FILE_ENCRYPTOR_H_
#define FILE_ENCRYPTOR_H_


int rsa_key_generate(char *p_file, char *p_password);

int encrypt_file(char *p_file_rsa_pub_key, char *p_file_in);

int decrypt_file(char *p_file_rsa_priv_key, char *p_password, char *p_file);

void crypto_tests();

#endif /* FILE_ENCRYPTOR_H_ */
