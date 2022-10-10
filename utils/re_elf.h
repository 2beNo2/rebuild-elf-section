#ifndef RE_ELF_H
#define RE_ELF_H

#include <stdint.h>
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__LP64__)
#define ElfW(type) Elf64_ ## type
#else
#define ElfW(type) Elf32_ ## type
#endif

typedef struct{
    const char  *pathname;
    
    ElfW(Addr)  base_addr;
    ElfW(Phdr)  *phdr;
    ElfW(Dyn)   *dynamic_tab;       
    ElfW(Word)  dynamic_sz;

    const char  *shstrtab;

    ElfW(Addr)  preinit_array_tab;
    ElfW(Word)  preinit_array_sz;
    ElfW(Addr)  init_array_tab;
    ElfW(Word)  init_array_sz;
    ElfW(Addr)  finit_array_tab;
    ElfW(Word)  finit_array_sz;
    
    ElfW(Addr)  hash_tab;
    uint32_t    hash_sz;
    //ElfW(Addr)  gnu_hash_addr;

    ElfW(Addr)  dynstr_tab;
    ElfW(Word)  dynstr_sz;
    ElfW(Sym)   dynsym_tab; 
    ElfW(Word)  dynsym_sz;

    int         is_use_rela;
    ElfW(Addr)  relplt_tab;
    ElfW(Word)  relplt_sz;
    ElfW(Addr)  reldyn_tab;
    ElfW(Word)  reldyn_sz;

    ElfW(Addr)  got_tab;
    ElfW(Addr)  plt_tab;

    ElfW(Addr)  text_tab;

} re_elf_t;

#ifdef __cplusplus
}
#endif

#endif //RE_ELF_H
