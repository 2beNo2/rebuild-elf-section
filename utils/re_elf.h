#ifndef RE_ELF_H
#define RE_ELF_H

#include <stdint.h>
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__aarch64__)
#define ElfW(type) Elf64_ ## type
#else
#define ElfW(type) Elf32_ ## type
#endif

typedef struct
{
    const char  *pathname;
    char  *new_pathname;
    char  *shstrtab;

    ElfW(Addr)  base_addr;
    ElfW(Ehdr)  *ehdr;
    ElfW(Phdr)  *phdr;
    ElfW(Dyn)   *dynamic_tab;       
    ElfW(Xword) dynamic_sz;

    uint32_t    file_sz;
    ElfW(Half)  shent_sz;

    ElfW(Addr)  preinit_array_addr;
    ElfW(Off)   preinit_array_off;
    ElfW(Xword) preinit_array_sz;
    ElfW(Addr)  init_array_addr;
    ElfW(Off)   init_array_off;
    ElfW(Xword) init_array_sz;
    ElfW(Addr)  finit_array_addr;
    ElfW(Off)   finit_array_off;
    ElfW(Xword) finit_array_sz;
    
    ElfW(Addr)  hash_addr;
    ElfW(Off)   hash_off;
    ElfW(Xword) hash_sz;

    ElfW(Addr)  dynstr_addr;
    ElfW(Off)   dynstr_off;
    ElfW(Xword) dynstr_sz;

    ElfW(Addr)  dynsym_addr; 
    ElfW(Off)   dynsym_off;
    ElfW(Xword) dynsym_ent;
    ElfW(Xword) dynsym_sz;

    int         is_use_rela;
    ElfW(Addr)  relplt_addr;
    ElfW(Off)   relplt_off;
    ElfW(Xword) relplt_sz;
    ElfW(Addr)  reldyn_addr;
    ElfW(Off)   reldyn_off;
    ElfW(Xword) reldyn_sz;

    ElfW(Addr)  plt_addr;
    ElfW(Off)   plt_off;
    ElfW(Xword) plt_sz;

    ElfW(Addr)  got_addr;
    ElfW(Off)   got_off;
    ElfW(Xword) got_sz;

    ElfW(Addr)  text_addr;
    ElfW(Off)   text_off;
    ElfW(Xword) text_sz;

} re_elf_t;

int  re_elf_check_elfheader(uintptr_t base_addr);
int  re_elf_init(re_elf_t *self, uintptr_t base_addr, const char *pathname, uint32_t file_sz);
int  re_elf_rewrite(re_elf_t *self);
void re_elf_destructor(re_elf_t *self);

#ifdef __cplusplus
}
#endif

#endif //RE_ELF_H
