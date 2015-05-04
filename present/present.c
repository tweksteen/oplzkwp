#include <stdint.h>

#include "present.h"

void present_encrypt(uint64_t *buffer, uint64_t *dst, uint16_t n, uint64_t *key)
{
  int i, k, w, round;
	uint16_t sBoxValue;
	int sBoxNr=0;
	uint64_t temp;
	uint64_t subkey[32];
	uint64_t state;

  for(w=0; w < n; w++)
  {
    state = ((uint64_t *)buffer)[w];
    for(round=0;round<32;round++)
		{
			subkey[round] = key[1];
			temp = key[1];
			key[1] <<= 61;
			key[1] |= (key[0]<<45);
			key[1] |= (temp>>19);
			key[0] = (temp>>3)&0xFFFF;

			temp = key[1]>>60;
			key[1] &=	0x0FFFFFFFFFFFFFFF;
			temp = sBox4[temp];
			key[1] |= temp<<60;

			key[0] ^= ( ( (round+1) & 0x01 ) << 15 );
			key[1] ^= ( (round+1) >> 1 );
		}

		for(i=0;i<31;i++)
		{
			state ^= subkey[i];
			for(sBoxNr=0;sBoxNr<16;sBoxNr++)
			{
				sBoxValue = state & 0xF;
				state &=	0xFFFFFFFFFFFFFFF0;
				state |=	sBox4[sBoxValue];
				state = rotate4l_64(state);
			}
			temp = 0;
			for(k=0;k<64;k++)
			{
				int position = (16*k) % 63;
				if(k == 63)
					position = 63;
				temp |= ((state>>k) & 0x1) << position;
			}
			state=temp;
		}
		state ^= subkey[31];
    dst[w] = state;
  }
}

void present_decrypt(uint64_t *buffer, uint64_t *dst, uint16_t n, uint64_t *key)
{
  int i, k, w, round;
	uint16_t sBoxValue;
	int sBoxNr=0;
	uint64_t temp;
	uint64_t subkey[32];
  uint64_t state;

  for(w=0; w < n; w++)
  {
    state = ((uint64_t *)buffer)[w];
		for(round=0; round<32; round++)
		{
			subkey[round] = key[1];
			temp = key[1];
			key[1] <<= 61;
			key[1] |= (key[0]<<45);
			key[1] |= (temp>>19);
			key[0] = (temp>>3)&0xFFFF;

			temp = key[1]>>60;
			key[1] &=	0x0FFFFFFFFFFFFFFF;
			temp = sBox4[temp];
			key[1] |= temp<<60;

			key[0] ^= ( ( (round+1) & 0x01 ) << 15 );
			key[1] ^= ( (round+1) >> 1 );
		}
		for(i = 31; i>0; i--)
		{
			state ^= subkey[i];
			temp = 0;
			for(k = 0;k<64;k++)
			{
				int position = (4*k) % 63;
				if(k == 63)
					position = 63;
				temp |= ((state>>k) & 0x1) << position;
			}
			state=temp;
			for(sBoxNr=0;sBoxNr<16;sBoxNr++)
			{
				sBoxValue = state & 0xF;
				state &=	0xFFFFFFFFFFFFFFF0;
				state |=	invsBox4[sBoxValue];
				state = rotate4l_64(state);
			}
		}
		state ^= subkey[0];
    dst[w] = state;
  }
}

