#ifndef piotr
#define piotr

#include <inttypes.h>
#include <stdio.h>

#define HASH_LENGTH 32
#define HASH_HEX_LEN 64 // length of longest hash string (excluding terminating null)

char* bin2hex(uint8_t* hash);

#endif
