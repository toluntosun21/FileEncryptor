# FileEncryptor
A simple file encryption program that implements an RSA-AES hybrid encryption scheme.

### Features    

#### Key generation
Generates RSA public private key pair and encrypts the generated private key pair using AES256 with counter mode. AES key is derived from the passphrase given with the -p option, using SHA3-256. Randomly generated nonce for AES256-CTR encryption is appended to the output file that stores the encryption of RSA private key.

    ./FileEncryptor.exe -k -rmy_rsa_key -pblack_eagles_fly_high


#### File encryption
Encrypts the input file with AES256-CTR. Randomly generated AES256 key is encrypted with the provided RSA public key and saved to file system as well as the CTR nonce.

    ./FileEncryptor.exe -e -rmy_rsa_key -fsome_text_file.txt


#### File decryption
First, derives the secret key from the passphrase following the same procedure in key generation. Then decrypts the RSA private key using the derived AES256 key in CTR mode. Then, uses the decrypted RSA private key to decrypt the AES256 key which is used for the file encryption / decryption, inverting the process in file encryption phase. The latter AES256 key is used to decrypt the the file.

    ./FileEncryptor.exe -d -rmy_rsa_key -fsome_text_file.txt -pblack_eagles_fly_high

#### Crypto tests

    ./FileEncryptor.exe -t

### Dependencies
- GMP 5.0.4

### Notes
- This software is developed for educational purposes and it is not side-channel resistant.
- Random number generation is performed with the RDRAND instruction of Intel x86 architecture, and post-processed with SHA3-256.
- AES algorithm is implemented using AES-NI instruction set of Intel x86 architecture.
- The software uses 2048-bit RSA modulus by default but it can be changed from the source easily.
