#include "piotr.h"

static char buffer[HASH_HEX_LEN+1];  // must be big enough for longest string and the 

char* bin2hex(uint8_t* hash)
{
	for(int i = 0; i < HASH_LENGTH; i++)
	{
		sprintf(buffer+2*i, "%02x", hash[i]);
	}
	buffer[HASH_HEX_LEN] = 0;
	return buffer;
}
