#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>

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
  for(i=0; i < hdr->e_shnum; i++) {
    if(!strcmp(elf_lookup_sh_string(hdr, elf_section(hdr, i)->sh_name), name))
      return elf_section(hdr, i);
  }
  return NULL;
}

static inline char *elf_lookup_string(Elf32_Ehdr *hdr, int offset) {
  char *strtab = (char *) hdr + (elf_section_by_name(hdr, ".strtab")->sh_offset);
  if(strtab == NULL) return NULL;
  return strtab + offset;
}

Elf32_Sym *elf_sym(Elf32_Ehdr *hdr, char *name){
  Elf32_Shdr *shdr_sym;
  Elf32_Sym  *sym, *t;
  int i, entries;

  shdr_sym = elf_section_by_name(hdr, ".symtab");
  sym = (Elf32_Sym *)((char *)hdr + shdr_sym->sh_offset);
  entries = shdr_sym->sh_size / shdr_sym->sh_entsize;
  for(i=0; i < entries; i++) {
    t = (Elf32_Sym *)((char *) sym + (shdr_sym->sh_entsize * i));
    if (!strcmp(elf_lookup_string(hdr, t->st_name), name))
      return t;
  }
  return NULL;
}

Elf32_Sym *elf_sym_at(Elf32_Ehdr *hdr, uint32_t offset){
  Elf32_Shdr *shdr_sym;
  Elf32_Sym  *sym, *t;
  int i, entries;

  shdr_sym = elf_section_by_name(hdr, ".symtab");
  sym = (Elf32_Sym *)((char *)hdr + shdr_sym->sh_offset);
  entries = shdr_sym->sh_size / shdr_sym->sh_entsize;
  for(i=0; i < entries; i++) {
    t = (Elf32_Sym *)((char *) sym + (shdr_sym->sh_entsize * i));
    if(t->st_value == offset)
      return t;
  }
  return NULL;
}
