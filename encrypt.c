#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <elf.h>
#include <sys/mman.h>

const uint16_t invsBox4[] = {0x5,0xe,0xf,0x8,0xC,0x1,0x2,0xD,0xB,0x4,0x6,0x3,0x0,0x7,0x9,0xA};
const uint64_t sBox4[] = {0xc,0x5,0x6,0xb,0x9,0x0,0xa,0xd,0x3,0xe,0xf,0x8,0x4,0x7,0x1,0x2};

#define high1_64(h1in) 			( (uint64_t)h1in >> 63 )	//msb as lsb
#define high4_64(h4in) 			( (uint64_t)h4in >> 60 )	//4 msb as lsb
#define rotate1l_64(r1lin)	 ( high1_64(r1lin) | ( r1lin << 1 ) )	//input rotated left (1x)
#define rotate4l_64(r4lin)	 ( high4_64(r4lin) | ( r4lin << 4 ) )	//input rotated left (4x)

void encrypt(uint64_t *buffer, uint64_t *dst, uint16_t n, uint64_t *key)
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

static inline Elf32_Shdr *elf_sheader(Elf32_Ehdr *hdr) {
  return (Elf32_Shdr *)((int)hdr + hdr->e_shoff);
}
 
static inline Elf32_Shdr *elf_section(Elf32_Ehdr *hdr, int idx) {
  return &elf_sheader(hdr)[idx];
}

static inline char *elf_str_table(Elf32_Ehdr *hdr) {
  if(hdr->e_shstrndx == SHN_UNDEF) return NULL;
  return (char *)hdr + elf_section(hdr, hdr->e_shstrndx)->sh_offset;
}
 
static inline char *elf_lookup_sh_string(Elf32_Ehdr *hdr, int offset) {
  char *shstrtab = elf_str_table(hdr);
  if(shstrtab == NULL) return NULL;
  return shstrtab + offset;
}

static Elf32_Shdr *elf_section_by_name(Elf32_Ehdr *hdr, char *name){
  int i;
  for(i=0; i< hdr->e_shnum; i++) {
    if(!strcmp(elf_lookup_sh_string(hdr, elf_section(hdr, i)->sh_name), name))
      return elf_section(hdr, i);
  }
  return NULL;
}

static inline char *elf_lookup_string(Elf32_Ehdr *hdr, int offset) {
  char *strtab = (char *)elf_section_by_name(hdr, ".strtab");
  printf("%lx\n", (int *)strtab - (int *)hdr);
  if(strtab == NULL) return NULL;
  return strtab + offset;
}

static Elf32_Sym *elf_sym(Elf32_Ehdr *hdr, char *name){
  Elf32_Shdr *shdr_sym;
  Elf32_Sym  *sym, *t;
  int i, entries;

  shdr_sym = elf_section_by_name(hdr, ".symtab");
  sym = (Elf32_Sym *)((int)hdr + shdr_sym->sh_offset);
  entries = shdr_sym->sh_size / shdr_sym->sh_entsize;
  for(i=0; i < entries; i++) {
    t = (Elf32_Sym *)((char *) sym + (shdr_sym->sh_entsize * i)); 
    printf("%d %x %d %x %x\n", i, t, t->st_size, t->st_name, (int *)elf_lookup_string(hdr, (int)t->st_name) - (int *)hdr);
  }
}

int main(void)
{
  int fd, i;
  size_t size;
  struct stat s;
  uint32_t stage;
  Elf32_Ehdr *ehdr;
  Elf32_Shdr *shdr_sym;

  uint64_t buffer[0x1000];
  uint64_t key[] = {0x1, 0x4};
  char *to_encrypt[] = { "second_stage", "third_stage", NULL };

  fd = open("past", O_RDWR);

  fstat(fd, &s);
  size = s.st_size;

  ehdr = mmap((caddr_t)0, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  
  shdr_sym = elf_section_by_name(ehdr, ".symtab");
  printf("%lx\n", (char *)elf_section_by_name(ehdr, ".strtab"));
  elf_sym(ehdr, "second_stage");

  i = 0;
  while(to_encrypt[i] != NULL)
  {
    printf("Encrypting %s...\n", to_encrypt[i]);
    //find stage address
    stage = 0xd20;

    // encrypt in place
    encrypt(buffer, buffer, 3, key);

    i++;
  }

  close(fd);
  return 0;
}
