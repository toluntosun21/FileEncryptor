#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include "crypto_conf.h"
#include "rsa.h"
#include "aes.h"
#include "file_encryptor.h"



enum choice{HELP, TEST, KEYGEN, ENCRYPT, DECRYPT};

int main(int argc, char **argv)
{

	printf("Welcome to the File Encryptor\n");

	int l_choice = -1;
	char *l_password = NULL;
	char *l_rsafile = NULL;
	char *l_infile = NULL;

	int c;


	while ((c = getopt (argc, argv, "htkedp:r:f:")) != -1)
		switch (c)
		  {
		  case 'h':
			l_choice = HELP;
			break;
		  case 't':
			l_choice = TEST;
			break;
		  case 'k':
			l_choice = KEYGEN;
			break;
		  case 'e':
			l_choice = ENCRYPT;
			break;
		  case 'd':
			l_choice = DECRYPT;
			break;
		  case 'p':
			  l_password = optarg;
			break;
		  case 'r':
			  l_rsafile = optarg;
			break;
		  case 'f':
			  l_infile = optarg;
			break;
		  case '?':
			return 1;
		  default:
			return 2;
		  }

	if (l_choice == HELP)
	{
		printf("\nUsage example:\n\n");
		printf("./FileEncryptor.exe -k -rmy_rsa_key -pblack_eagles_fly_high\n\n");
		printf("./FileEncryptor.exe -e -rmy_rsa_key -fsome_text_file.txt\n\n");
		printf("./FileEncryptor.exe -d -rmy_rsa_key -fsome_text_file.txt -pblack_eagles_fly_high\n\n\n");
	}
	else if (l_choice == TEST)
	{
		crypto_tests();
	}
	else if(l_choice == KEYGEN)
	{
		if (l_rsafile == NULL)
		{
			printf("File name for saving the RSA public-private key pair must be defined with the -r option\n");
			return 3;
		}
		else if (l_password == NULL)
		{
			printf("Pass phrase for encrypting the RSA private key must be defined with the -p option\n");
			return 4;
		}
		else
		{
			return rsa_key_generate(l_rsafile, l_password);
		}
	}
	else if(l_choice == ENCRYPT)
	{
		if (l_rsafile == NULL)
		{
			printf("File name that stores the RSA public key must be defined with the -r option (without the .pub post-fix)\n");
			return 3;
		}
		else if (l_infile == NULL)
		{
			printf("Input file name must be defined with the -f option\n");
			return 4;
		}
		else
		{
			return encrypt_file(l_rsafile, l_infile);
		}
	}
	else if(l_choice == DECRYPT)
	{
		if (l_rsafile == NULL)
		{
			printf("File name that stores the RSA public key must be defined with the -r option (without the .pub post-fix)\n");
			return 3;
		}
		else if (l_infile == NULL)
		{
			printf("Input file name must be defined with the -f option (without the .e post-fix)\n");
			return 4;
		}
		else if (l_password == NULL)
		{
			printf("Pass phrase for decrypting the RSA private key must be defined with the -p option\n");
			return 5;
		}
		else
		{
			return decrypt_file(l_rsafile, l_password, l_infile);
		}
	}
	else
	{
		printf("Use -h option for help, -t option for test\n");
		return 6;
	}



	printf("File Encryptor has finished running\n");

	return 0;

}
