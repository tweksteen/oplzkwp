#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <elf.h>
#include <string.h>

#include "elf/elf_raw.h"

#define LOG_PREFIX "[loader] "
#define TEXT_OFFSET 0x1000    /* .text offset, maybe be confirmed via section
				 info */

#ifdef DEBUG
#define _log(format,args...) printf(LOG_PREFIX format, ## args)
#else
#define _log(format,args...)
#endif

extern void present_decrypt(uint64_t *, uint64_t *, uint16_t, uint64_t *);
extern void present_encrypt(uint64_t *, uint64_t *, uint16_t, uint64_t *);
extern void blake224_hash( uint8_t *, const uint8_t *, uint64_t);
void marker(void) __attribute__((optimize("-O0")));

void marker(void){};

uint32_t get_fct_size(uint32_t offset)
{
	int fd;
	uint32_t size;
	struct stat s;
	Elf32_Ehdr *ehdr;
	Elf32_Sym *sym;

	fd = open("/proc/self/exe", O_RDONLY);
	if(fd < 0){
		 _log("[! /proc]\n");
		exit(EXIT_FAILURE);
	}

	fstat(fd, &s);
	ehdr = mmap(NULL, s.st_size, PROT_READ, MAP_SHARED, fd, 0);
	sym = elf_sym_at(ehdr, offset);

	if(sym == NULL) {
		_log("[! %08x]\n", offset);
		exit(EXIT_FAILURE);
	}
	size = sym->st_size;
	munmap(ehdr, s.st_size);
	close(fd);
	return size;
}

void decrypt_and_call(void *stage)
{
	uint32_t stage_addr = (uint32_t) stage;
	uint32_t aligned_stage_addr = stage_addr & (~ 0xff);
	void (*fct)();
	int ret, key_length;
	long page_size;
	uint32_t page_mask, base_addr, stage_size, stage_pages;
	uint64_t key[4] = { [0 ... 3]  = 0x0 };
	uint8_t *b;

	page_size = sysconf(_SC_PAGESIZE);
	page_mask = ~ (page_size - 1);

	fct = stage;
	base_addr = (((int) &marker & page_mask) - TEXT_OFFSET);
	stage_size = get_fct_size(stage_addr - base_addr);
	if(stage_size == 0) {
		_log("Empty symbol size: %x\n", stage_addr);
		exit(EXIT_FAILURE);
	}
	stage_pages = stage_size/page_size + 1;
	key_length = asprintf(((char **)&b), LOG_PREFIX "%08x %08x",
			stage_addr-base_addr, stage_size);
	if(key_length <= 0) {
		_log("key_length == %x\n", key_length);
		exit(EXIT_FAILURE);
	}

	blake224_hash((uint8_t *)key, b, key_length);
	_log("opening @%x: size=%x pages=%x key=%llx:%llx\n",
		stage_addr, stage_size, stage_pages, key[0], key[1]);
	ret = mprotect((void *)aligned_stage_addr, stage_pages,
		PROT_READ | PROT_WRITE);
	if(ret){
		_log("Is PaX around?\n");
		exit(EXIT_FAILURE);
	}
	present_decrypt((uint64_t *)stage, (uint64_t *)stage,
			stage_size / 8, key);
	mprotect((void *)aligned_stage_addr, stage_pages,
		 PROT_READ | PROT_EXEC);

	fct();

	blake224_hash((uint8_t *)key, b, key_length);
	_log("closing @%x: size=%x pages=%x key=%llx:%llx\n",
		stage_addr, stage_size, stage_pages, key[0], key[1]);
	mprotect((void *)aligned_stage_addr, stage_pages,
		 PROT_READ | PROT_WRITE);
	present_encrypt((uint64_t *)stage, (uint64_t *)stage,
			stage_size / 8, key);
	mprotect((void *)aligned_stage_addr, stage_pages,
		 PROT_READ | PROT_EXEC);

	free(b);
}
