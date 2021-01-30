#ifndef CRYPTO_CONF
#define CRYPTO_CONF


#include <stdint.h>

#define BYTE uint8_t
#define WORD uint32_t
#define RSA_MAX_PRECISION 128 // RSA-4096
#define RSA_MAX_PRE_PUBKEY 1


#define MILLER_RABIN_K 100

#define WORDS_TO_BITS(input) ((input) << 5)
#define WORDS_TO_BYTES(input) ((input) << 2)
#define BYTES_TO_WORDS(input) ((input) >> 2)
#define BITS_TO_BYTES(input) ((input) >> 3)
#define BYTES_TO_BITS(input) ((input) << 3)



#endif /* CRYPTO_CONF_H_ */
