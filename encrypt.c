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

#define LOG_PREFIX    "[crypt] "
#define STRING_MARKER "_marker_"

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
		addr = addr - elf_dot_text_vaddr(hdr) +
			elf_dot_text_offset(hdr);

		// bringing confusion to RE's brain
		key_length = asprintf(&b, "[loader] %08x %08x", sym->st_value,
					sym->st_size);
		blake224_hash((uint8_t *)key, (uint8_t *)b, key_length);
		free(b);

		printf(LOG_PREFIX "%s at:%x size:%x keys=%llx:%llx\n",
		       sname, addr, sym->st_size, key[0], key[1]);

		// encrypt in place
		present_encrypt((uint64_t *)((char *)hdr+addr),
			(uint64_t *)((char *)hdr+addr), sym->st_size/8, key);
	}
	return 0;
}

void encrypt_rodata(Elf32_Ehdr *hdr)
{
	char *b;
	int key_length;
	uint32_t ret, rodata_esize;
	uint64_t key[4] = { [0 ... 3]  = 0x0 };
	Elf32_Shdr *rodata = elf_section_by_name(hdr, ".rodata");

	ret = (uint32_t) memmem((void *)hdr+rodata->sh_offset, rodata->sh_size,
				STRING_MARKER, sizeof(STRING_MARKER));
	if((void *)ret != NULL)
	{
		ret += sizeof(STRING_MARKER);
		key_length = asprintf(&b, "[loader] %08x %08x",
				      rodata->sh_offset, rodata->sh_size);
		blake224_hash((uint8_t *)key, (uint8_t *)b, key_length);
		free(b);

		printf(LOG_PREFIX "rodata at:%x size:%x keys=%llx:%llx\n",
		       rodata->sh_offset, rodata->sh_size, key[0], key[1]);

		rodata_esize = rodata->sh_size -
			(ret - (uint32_t)hdr - rodata->sh_offset);

		printf(LOG_PREFIX "rodata_esize=%x\n", rodata_esize);
		present_encrypt((uint64_t *)((char *)ret),
			(uint64_t *)((char *)ret), (rodata_esize / 8), key);
	}
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
		perror(LOG_PREFIX);
		exit(EXIT_FAILURE);
	}
	fstat(fd, &s);
	size = s.st_size;
	ehdr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

	sym_foreach(ehdr, encrypt_symbol, "_e_");
	encrypt_rodata(ehdr);

	munmap(ehdr, size);

	close(fd);
	return 0;
}
