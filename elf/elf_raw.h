#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>

char *elf_lookup_string(Elf32_Ehdr *, int);
Elf32_Shdr *elf_section_by_name(Elf32_Ehdr *, char *);
uint32_t elf_dot_text_offset(Elf32_Ehdr *);
uint32_t elf_dot_text_vaddr(Elf32_Ehdr *);
Elf32_Sym *sym_foreach(Elf32_Ehdr *,
		       int (*f)(Elf32_Ehdr *, Elf32_Sym *, void *),
		       void *);
Elf32_Sym *elf_sym_at(Elf32_Ehdr *, uint32_t);
