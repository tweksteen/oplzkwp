#include <stdint.h>

const uint16_t invsBox4[] = {0x5,0xe,0xf,0x8,0xC,0x1,0x2,0xD,0xB,0x4,0x6,0x3,0x0,0x7,0x9,0xA};
const uint64_t sBox4[] = {0xc,0x5,0x6,0xb,0x9,0x0,0xa,0xd,0x3,0xe,0xf,0x8,0x4,0x7,0x1,0x2};

#define high1_64(h1in) 			( (uint64_t)h1in >> 63 )	//msb as lsb
#define high4_64(h4in) 			( (uint64_t)h4in >> 60 )	//4 msb as lsb
#define rotate1l_64(r1lin)	 ( high1_64(r1lin) | ( r1lin << 1 ) )	//input rotated left (1x)
#define rotate4l_64(r4lin)	 ( high4_64(r4lin) | ( r4lin << 4 ) )	//input rotated left (4x)


void decrypt(uint64_t *buffer, uint64_t *dst, uint16_t n, uint64_t *key)
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

