#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <elf.h>
#include <sys/mman.h>

#define LOG_PREFIX "[crypt] "

extern void encrypt(uint64_t *, uint64_t *, uint16_t, uint64_t *);
extern Elf32_Sym *elf_sym(Elf32_Ehdr *, char *);
extern void blake224_hash( uint8_t *, const uint8_t *, uint64_t);

int main(void)
{
  int fd, i, key_length;
  size_t size;
  struct stat s;
  uint32_t stage;
  Elf32_Ehdr *ehdr;
  Elf32_Sym *sym;
  char *b;

  uint64_t key[4] = { [0 ... 3]  = 0x0 };
  char *to_encrypt[] = { "second_stage", "third_stage", NULL };

  fd = open("oplzkwp", O_RDWR);
  if(fd < 0){
	errx(EXIT_FAILURE, "File not found\n");
  }
  fstat(fd, &s);
  size = s.st_size;
  ehdr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

  i = 0;
  while(to_encrypt[i] != NULL)
  {
    printf(LOG_PREFIX "Encrypting %s...\n", to_encrypt[i]);
    sym = elf_sym(ehdr, to_encrypt[i]);
    if(!sym){
      printf(LOG_PREFIX "[-] Unable to find the symbol: %s\n", to_encrypt[i]);
    }

    key_length = asprintf(&b, "[loader] %08x %08x", sym->st_value, sym->st_size);
    blake224_hash((uint8_t *)key, b, key_length);

    printf(LOG_PREFIX "%s at:%x size:%x blocks:%d keys=%llx:%llx\n", to_encrypt[i], sym->st_value,
		sym->st_size, sym->st_size/8,key[0], key[1]);
    // encrypt in place
    encrypt((uint64_t *)((char *)ehdr+sym->st_value),
		(uint64_t *)((char *)ehdr+sym->st_value), sym->st_size/8, key);

    i++;
  }

  close(fd);
  return 0;
}
