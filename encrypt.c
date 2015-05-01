#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <elf.h>

#include "elf/elf_raw.h"

#ifndef EXEC_NAME
#define EXEC_NAME "oplzkwp"
#endif

#define LOG_PREFIX "[crypt] "

extern void present_encrypt(uint64_t *, uint64_t *, uint16_t, uint64_t *);
extern void blake224_hash( uint8_t *, const uint8_t *, uint64_t);

static int encrypt_symbol(Elf32_Ehdr *hdr, Elf32_Sym *sym, void *prefix)
{
  int key_length;
  char *sname;
  char *b;
  uint64_t key[4] = { [0 ... 3]  = 0x0 };
  uint32_t addr;

  sname = elf_lookup_string(hdr, sym->st_name);
  if (strstr(sname, prefix) == sname) {
    printf(LOG_PREFIX "Encrypting %s...\n", sname);
    addr = sym->st_value;
    addr = addr - elf_dot_text_vaddr(hdr) + elf_dot_text_offset(hdr);

    // Use symbol value for key
    key_length = asprintf(&b, "[loader] %08x %08x", sym->st_value,
			  sym->st_size);
    blake224_hash((uint8_t *)key, (uint8_t *)b, key_length);

    printf(LOG_PREFIX "%s at:%x size:%x blocks:%d keys=%llx:%llx\n", sname,
		addr, sym->st_size, sym->st_size/8,key[0], key[1]);

    // encrypt in place
    present_encrypt((uint64_t *)((char *)hdr+addr),
		(uint64_t *)((char *)hdr+addr), sym->st_size/8, key);
    }
  return 0;
}

int main(int argc, char **argv)
{
  int fd;
  size_t size;
  struct stat s;
  Elf32_Ehdr *ehdr;
  char *target;

  target = (argc > 1) ? argv[1] : EXEC_NAME;

  fd = open(target, O_RDWR);
  if(fd < 0){
	perror("File not found\n");
	exit(EXIT_FAILURE);
  }
  fstat(fd, &s);
  size = s.st_size;
  ehdr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

  sym_foreach(ehdr, encrypt_symbol, "_e_");

  close(fd);
  return 0;
}
