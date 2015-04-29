#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <elf.h>

#define TEXT_OFFSET 0x2000
#define LOG_PREFIX "[loader] "

extern void second_stage(void);
extern void decrypt(uint64_t *, uint64_t *, uint16_t, uint64_t *);
extern Elf32_Sym *elf_sym_at(Elf32_Ehdr *, uint32_t);
extern void blake224_hash( uint8_t *, const uint8_t *, uint64_t);

uint32_t get_fct_size(uint32_t offset)
{
  int fd;
  uint32_t size;
  struct stat s;
  Elf32_Ehdr *ehdr;
  Elf32_Sym *sym;

  fd = open("/proc/self/exe", O_RDONLY);
  if(fd < 0){
	errx(EXIT_FAILURE, "[!]\n");
  }
  fstat(fd, &s);
  ehdr = mmap(NULL, s.st_size, PROT_READ, MAP_SHARED, fd, 0);
  sym = elf_sym_at(ehdr, offset);
  if(sym == NULL) {
	errx(EXIT_FAILURE, "[!]\n");
  }
  size = sym->st_size;
  munmap(ehdr, s.st_size);
  close(fd);
  return size;
}

void decrypt_and_call(void *stage)
{
  uint32_t stage_addr = (uint32_t) stage;
  void (*fct)();
  int ret, key_length;
  long page_size;
  uint32_t page_mask, base_addr, stage_size, stage_pages;
  uint64_t key[4] = { [0 ... 3]  = 0x0 };
  char *b;

  page_size = sysconf(_SC_PAGESIZE);
  page_mask = ~ (page_size - 1);

  fct = stage;
  base_addr = ((int) &decrypt_and_call & page_mask) - TEXT_OFFSET;
  stage_size = get_fct_size(stage_addr - base_addr);
  stage_pages = stage_size/page_size + 1;

  key_length = asprintf(&b, LOG_PREFIX "%08x %08x", stage_addr-base_addr,
			stage_size);
  blake224_hash((uint8_t *)key, b, key_length);

  printf(LOG_PREFIX "stage[%lx]: %x %x %lx %llx %llx\n", stage_addr,
	 stage_size, key_length, stage_pages, key[0], key[1]);

  free(b);

  ret = mprotect((void *)stage_addr, stage_pages, PROT_READ | PROT_WRITE);
  if(ret){
	errx(EXIT_FAILURE, LOG_PREFIX "Is PaX around?\n");
  }

  decrypt((uint64_t *)stage, (uint64_t *)stage, stage_size / 8, key);
  mprotect((void *)stage_addr, stage_pages, PROT_READ | PROT_EXEC);
  fct();
}

