/*
 * file_encryptor.c
 *
 *  Created on: 20 Oca 2021
 *      Author: toluntosun
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "crypto_conf.h"
#include "rsa.h"
#include "sha256.h"
#include "aes.h"
#include "random.h"

#define RSA_PRECISION 64 // in words
#define AES_KEYLEN 32 // in bytes

int rsa_key_generate(char *p_file, char *p_password)
{
	int l_ret = 0;
	uint32_t l_passwordlen;
	rsa_pubkey l_pubkey;
	rsa_privatekey l_privkey;
	BYTE l_aeskey[SHA256_HASH_SIZE];
	aes_ctx l_aes_ctx;
	BYTE l_nonce[8];
	BYTE *l_encrypted_rsa_d;
	char *l_filename_pub, *l_filename_priv;
	FILE *l_keyfile;

	l_ret = rsa_paramgen(&l_pubkey, &l_privkey, RSA_PRECISION);
	if (l_ret)
	{
		printf("Error in RSA-%d public-private key pair generation\n", WORDS_TO_BITS(RSA_PRECISION));
		l_ret = -1;
		goto rsa_key_generate_end;
	}

	// Generate AES256 from the pass phrase

	l_passwordlen = strlen(p_password);
	sha256(l_aeskey, (BYTE*) p_password, l_passwordlen);

	l_ret = random_randbytes_sha256whitening(l_nonce, 8);
	if (l_ret)
	{
		printf("Error in nonce generation\n");
		l_ret = -2;
		goto rsa_key_generate_end;
	}

	l_ret = aes_ctr_init(&l_aes_ctx, l_aeskey, AES_KEYLEN, l_nonce);
	if (l_ret)
	{
		printf("Error in AES%d key expansion\n", BYTES_TO_BITS(AES_KEYLEN));
		l_ret = -3;
		goto rsa_key_generate_end;
	}

	// Encrypt RSA private key with AES256 CTR

	l_encrypted_rsa_d = malloc(WORDS_TO_BYTES(l_privkey.precision));

	l_ret = aes_ctr_update(l_encrypted_rsa_d, (BYTE*) l_privkey.d, WORDS_TO_BYTES(l_privkey.precision), &l_aes_ctx);
	if (l_ret)
	{
		printf("Error in AES%d encryption of RSA private key\n", BYTES_TO_BITS(AES_KEYLEN));
		l_ret = -4;
		goto rsa_key_generate_end;
	}

	// Save public and private key

	l_filename_pub = malloc(strlen(p_file) + 5);
	strcpy(l_filename_pub, p_file);
	strcat(l_filename_pub, ".pub");
	l_keyfile = fopen(l_filename_pub, "wb");
	if (l_keyfile == NULL)
	{
		printf("Error in opening %s\n", l_filename_pub);
		l_ret = -5;
		goto rsa_key_generate_end;
	}
	else
	{
		fwrite((void *) &(l_pubkey.precision), sizeof(uint32_t), 1, l_keyfile);
		fwrite((void *) l_pubkey.n, sizeof(WORD), l_pubkey.precision, l_keyfile);
		fwrite((void *) &(l_pubkey.precision_pubkey), sizeof(uint32_t), 1, l_keyfile);
		fwrite((void *) l_pubkey.e, sizeof(WORD), l_pubkey.precision_pubkey, l_keyfile);
		fclose(l_keyfile);
	}

	l_filename_priv = malloc(strlen(p_file) + 6);
	strcpy(l_filename_priv, p_file);
	strcat(l_filename_priv, ".priv");
	l_keyfile = fopen(l_filename_priv, "wb");
	if (l_keyfile == NULL)
	{
		printf("Error in opening %s\n", l_filename_priv);
		l_ret = -6;
		goto rsa_key_generate_end;
	}
	else
	{
		fwrite((void *) &(l_privkey.precision), sizeof(uint32_t), 1, l_keyfile);
		fwrite((void *) l_privkey.n, sizeof(WORD), l_privkey.precision, l_keyfile);
		fwrite((void *) l_encrypted_rsa_d, sizeof(BYTE), WORDS_TO_BYTES(l_privkey.precision), l_keyfile);
		fwrite((void *) &(l_privkey.precision_pubkey), sizeof(uint32_t), 1, l_keyfile);
		fwrite((void *) l_privkey.e, sizeof(WORD), l_privkey.precision_pubkey, l_keyfile);
		fwrite((void *) l_nonce, sizeof(BYTE), sizeof(l_nonce), l_keyfile);
		fclose(l_keyfile);
	}

	printf("Successfully generated the RSA%d public(%s) - private(%s) key pair!\n", WORDS_TO_BITS(RSA_PRECISION), l_filename_pub, l_filename_priv);



rsa_key_generate_end:
	free(l_filename_pub);
	free(l_filename_priv);
	free(l_encrypted_rsa_d);

	return l_ret;
}


int encrypt_file(char *p_file_rsa_pub_key, char *p_file)
{
	int l_ret = 0;
	rsa_pubkey l_pubkey;
	char *l_filename_pk, *l_filename_sk, *l_filename_e;
	FILE *l_file, *l_file_out;
	WORD *l_aeskey;
	WORD *l_aeskey_enc;
	BYTE l_nonce[8];
	aes_ctx l_aes_ctx;
	BYTE l_aes_block[AES_BLOCKSIZE];
	BYTE l_aes_block_enc[AES_BLOCKSIZE];
	int l_read = 0;

	l_filename_pk = malloc(strlen(p_file_rsa_pub_key) + 5);
	strcpy(l_filename_pk, p_file_rsa_pub_key);
	strcat(l_filename_pk, ".pub");
	l_file = fopen(l_filename_pk, "rb");

	// Read RSA public key

	if (l_file == NULL)
	{
		printf("Error in opening %s\n", l_filename_pk);
		l_ret = -1;
		goto encrypt_file_end;
	}
	else
	{
		fread((void *) &(l_pubkey.precision), sizeof(uint32_t), 1, l_file);
		fread((void *) l_pubkey.n, sizeof(WORD), l_pubkey.precision, l_file);
		fread((void *) &(l_pubkey.precision_pubkey), sizeof(uint32_t), 1, l_file);
		fread((void *) l_pubkey.e, sizeof(WORD), l_pubkey.precision_pubkey, l_file);
		fclose(l_file);
	}

	// Generate AES key and nonce for file encryption

	l_aeskey = malloc(WORDS_TO_BYTES(l_pubkey.precision));
	memset(l_aeskey, 0x00, WORDS_TO_BYTES(l_pubkey.precision));
	l_aeskey_enc = malloc(WORDS_TO_BYTES(l_pubkey.precision));

	l_ret = random_randbytes_sha256whitening((BYTE*) l_aeskey, AES_KEYLEN);
	if (l_ret)
	{
		printf("Error in AES%d key generation\n", BYTES_TO_BITS(AES_KEYLEN));
		l_ret = -2;
		goto encrypt_file_end;
	}

	l_ret = random_randbytes_sha256whitening(l_nonce, sizeof(l_nonce));
	if (l_ret)
	{
		printf("Error in nonce generation\n");
		l_ret = -3;
		goto encrypt_file_end;
	}

	// Encrypt the AES secret key with RSA public key that is read from file, write to file with the nonce
	// (nonce is written open)

	l_ret = rsa_encrypt(l_aeskey_enc, l_aeskey, &l_pubkey);
	if (l_ret)
	{
		printf("Error in encryption of AES%d key with RSA public key\n", BYTES_TO_BITS(AES_KEYLEN));
		l_ret = -4;
		goto encrypt_file_end;
	}

	l_filename_sk = malloc(strlen(p_file) + 4);
	strcpy(l_filename_sk, p_file);
	strcat(l_filename_sk, ".sk");
	l_file = fopen(l_filename_sk, "wb");
	if (l_file == NULL)
	{
		printf("Error in opening %s\n", l_filename_sk);
		l_ret = -5;
		goto encrypt_file_end;
	}
	else
	{
		fwrite((void *) l_aeskey_enc, sizeof(WORD), l_pubkey.precision, l_file);
		fwrite((void *) l_nonce, sizeof(BYTE), sizeof(l_nonce), l_file);
		fclose(l_file);
	}


	// Encrypt the file with AES CTR

	l_ret = aes_ctr_init(&l_aes_ctx, (BYTE*) l_aeskey, AES_KEYLEN, l_nonce);
	if (l_ret)
	{
		printf("Error in AES%d key expansion\n", BYTES_TO_BITS(AES_KEYLEN));
		l_ret = -6;
		goto encrypt_file_end;
	}

	l_file = fopen(p_file, "rb");
	if (l_file == NULL)
	{
		printf("Error in opening %s\n", p_file);
		l_ret = -7;
		goto encrypt_file_end;
	}
	l_filename_e = malloc(strlen(p_file) + 3);
	strcpy(l_filename_e, p_file);
	strcat(l_filename_e, ".e");
	l_file_out = fopen(l_filename_e, "wb");
	if (l_file == NULL)
	{
		printf("Error in opening %s\n", l_filename_e);
		l_ret = -8;
		goto encrypt_file_end;
	}
	do
	{
		memset(l_aes_block, 0x00, AES_BLOCKSIZE);
		l_read = fread((void *) l_aes_block, sizeof(BYTE), AES_BLOCKSIZE, l_file);

		if (!l_read)
		{
			break;
		}

		l_ret = aes_ctr_update(l_aes_block_enc, l_aes_block, AES_BLOCKSIZE, &l_aes_ctx);
		if (l_ret)
		{
			printf("Error in AES%d encryption of the file\n", BYTES_TO_BITS(AES_KEYLEN));
			l_ret = -9;
			goto encrypt_file_end;
		}
		else
		{
			fwrite((void *) l_aes_block_enc, sizeof(BYTE), AES_BLOCKSIZE, l_file_out);
		}

	}
	while(l_read == AES_BLOCKSIZE);
	fclose(l_file);
	fclose(l_file_out);

	printf("Successfully encrypted the file '%s' into the file '%s'.\n", p_file, l_filename_e);
	printf("The encryption of the AES256 key with the RSA public key '%s', ", p_file_rsa_pub_key);
	printf("concatenated with the nonce for CTR mode are saved to '%s' !\n", l_filename_sk);

encrypt_file_end:

	free(l_aeskey);
	free(l_aeskey_enc);
	free(l_filename_pk);
	free(l_filename_sk);
	free(l_filename_e);

	return l_ret;
}


int decrypt_file(char *p_file_rsa_priv_key, char *p_password, char *p_file_in)
{
	int l_ret = 0, l_read = 0;
	uint32_t l_passwordlen;
	rsa_privatekey l_privkey;
	BYTE l_aeskey_rsa[SHA256_HASH_SIZE];
	aes_ctx l_aes_ctx_rsaprivkey, l_aes_ctx_file;
	char *l_filename_rsapriv, *l_filename_sk, *l_filename_e;
	FILE *l_rsapriv_file, *l_file_sk, *l_file_out, *l_file_in;
	BYTE *l_encrypted_rsa_d;
	BYTE l_nonce[8];
	WORD *l_aeskey_file_enc, *l_aeskey_file;
	BYTE l_aes_block[AES_BLOCKSIZE];
	BYTE l_aes_block_enc[AES_BLOCKSIZE];
	uint32_t l_nonzero_blocklen;


	// Read encrypted RSA private key

	l_filename_rsapriv = malloc(strlen(p_file_rsa_priv_key) + 6);
	strcpy(l_filename_rsapriv, p_file_rsa_priv_key);
	strcat(l_filename_rsapriv, ".priv");
	l_rsapriv_file = fopen(l_filename_rsapriv, "rb");
	if (l_rsapriv_file == NULL)
	{
		printf("Error in opening %s\n", l_filename_rsapriv);
		l_ret = -1;
		goto decrypt_file_end;
	}
	else
	{
		fread((void *) &(l_privkey.precision), sizeof(uint32_t), 1, l_rsapriv_file);
		l_encrypted_rsa_d = malloc(WORDS_TO_BYTES(l_privkey.precision));
		fread((void *) l_privkey.n, sizeof(WORD), l_privkey.precision, l_rsapriv_file);
		fread((void *) l_encrypted_rsa_d, sizeof(BYTE), WORDS_TO_BYTES(l_privkey.precision), l_rsapriv_file);
		fread((void *) &(l_privkey.precision_pubkey), sizeof(uint32_t), 1, l_rsapriv_file);
		fread((void *) l_privkey.e, sizeof(WORD), l_privkey.precision_pubkey, l_rsapriv_file);
		fread((void *) l_nonce, sizeof(BYTE), sizeof(l_nonce), l_rsapriv_file);
		fclose(l_rsapriv_file);
	}


	// Decryption of RSA private key d

	l_passwordlen = strlen(p_password);
	sha256(l_aeskey_rsa, (BYTE*) p_password, l_passwordlen);

	l_ret = aes_ctr_init(&l_aes_ctx_rsaprivkey, l_aeskey_rsa, AES_KEYLEN, l_nonce);
	if (l_ret)
	{
		printf("Error in AES%d key expansion\n", BYTES_TO_BITS(AES_KEYLEN));
		l_ret = -2;
		goto decrypt_file_end;
	}

	l_ret = aes_ctr_update((BYTE*) l_privkey.d, l_encrypted_rsa_d, WORDS_TO_BYTES(l_privkey.precision), &l_aes_ctx_rsaprivkey);
	if (l_ret)
	{
		printf("Error in AES%d decryption of RSA private key\n", BYTES_TO_BITS(AES_KEYLEN));
		l_ret = -3;
		goto decrypt_file_end;
	}


	// Read the .sk file and decrypt it using the RSA private key

	l_aeskey_file_enc = malloc(WORDS_TO_BYTES(l_privkey.precision));
	l_aeskey_file = malloc(WORDS_TO_BYTES(l_privkey.precision));

	l_filename_sk = malloc(strlen(p_file_in) + 4);
	strcpy(l_filename_sk, p_file_in);
	strcat(l_filename_sk, ".sk");
	l_file_sk = fopen(l_filename_sk, "rb");
	if (l_file_sk == NULL)
	{
		printf("Error in opening %s\n", l_filename_sk);
		l_ret = -4;
		goto decrypt_file_end;
	}
	else
	{
		fread((void *) l_aeskey_file_enc, sizeof(WORD), l_privkey.precision, l_file_sk);
		fread((void *) l_nonce, sizeof(BYTE), sizeof(l_nonce), l_file_sk);
		fclose(l_file_sk);
	}

	l_ret = rsa_decrypt(l_aeskey_file, l_aeskey_file_enc, &l_privkey);
	if (l_ret)
	{
		printf("Error in decryption of AES%d key with RSA public key\n", BYTES_TO_BITS(AES_KEYLEN));
		l_ret = -5;
		goto decrypt_file_end;
	}


	// Decrypt the file with AES CTR

	l_ret = aes_ctr_init(&l_aes_ctx_file, (BYTE*) l_aeskey_file, AES_KEYLEN, l_nonce);
	if (l_ret)
	{
		printf("Error in AES%d key expansion\n", BYTES_TO_BITS(AES_KEYLEN));
		l_ret = -6;
		goto decrypt_file_end;
	}

	l_file_out = fopen(p_file_in, "wb");
	if (l_file_out == NULL)
	{
		printf("Error in opening %s.\n", p_file_in);
		l_ret = -7;
		goto decrypt_file_end;
	}
	l_filename_e = malloc(strlen(p_file_in) + 3);
	strcpy(l_filename_e, p_file_in);
	strcat(l_filename_e, ".e");
	l_file_in = fopen(l_filename_e, "rb");
	if (l_file_in == NULL)
	{
		printf("Error in opening %s. Please input the file name of the decryption without the '.e' post-fix\n", p_file_in);
		l_ret = -8;
		goto decrypt_file_end;
	}
	do
	{
		l_read = fread((void *) l_aes_block_enc, sizeof(BYTE), AES_BLOCKSIZE, l_file_in);

		if (!l_read)
		{
			break;
		}

		l_ret = aes_ctr_update(l_aes_block, l_aes_block_enc, AES_BLOCKSIZE, &l_aes_ctx_file);
		if (l_ret)
		{
			printf("Error in AES%d encryption of the file\n", BYTES_TO_BITS(AES_KEYLEN));
			l_ret = -9;
			goto decrypt_file_end;
		}
		else
		{
			for (l_nonzero_blocklen = 0; l_nonzero_blocklen < AES_BLOCKSIZE && l_aes_block[l_nonzero_blocklen]; l_nonzero_blocklen++);
			fwrite((void *) l_aes_block, sizeof(BYTE), l_nonzero_blocklen, l_file_out);
		}

	}
	while(l_read == AES_BLOCKSIZE);
	fclose(l_file_in);
	fclose(l_file_out);

	printf("Successfully decrypted the file '%s.priv' into the file '%s'.\n", p_file_in, p_file_in);

decrypt_file_end:

	free(l_filename_rsapriv);
	free(l_filename_e);
	free(l_filename_sk);
	free(l_aeskey_file_enc);
	free(l_aeskey_file);
	free(l_encrypted_rsa_d);

	return l_ret;
}


void crypto_tests()
{
	int l_ret;

	l_ret = rsa_test(10, 512);
	if (l_ret == 0)
	{
		printf("RSA Tests Passes\n");
	}
	else
	{
		printf("RSA Tests Fails: %d\n", l_ret);
	}

	l_ret = aes_ctr_test(10);
	if (l_ret == 0)
	{
		printf("AES Tests Passes\n");
	}
	else
	{
		printf("AES Tests Fails: %d\n", l_ret);
	}


}
