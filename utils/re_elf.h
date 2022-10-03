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
    const char *pathname;
    
    ElfW(Addr)  base_addr;
    ElfW(Addr)  bias_addr;
    
    ElfW(Ehdr) *ehdr;
    ElfW(Phdr) *phdr;

    ElfW(Dyn)  *dyn;     //.dynamic
    ElfW(Word)  dyn_sz;

    const char *strtab;  //.dynstr (string-table)
    ElfW(Sym)  *symtab;  //.dynsym (symbol-index to string-table's offset)

    ElfW(Addr)  relplt;  //.rel.plt or .rela.plt
    ElfW(Word)  relplt_sz;
    
    ElfW(Addr)  reldyn;  //.rel.dyn or .rela.dyn
    ElfW(Word)  reldyn_sz;
    
    ElfW(Addr)  relandroid;  //android compressed rel or rela
    ElfW(Word)  relandroid_sz;

    //for ELF hash
    uint32_t   *bucket;
    uint32_t    bucket_cnt;
    uint32_t   *chain;
    uint32_t    chain_cnt;  //invalid for GNU hash

    //append for GNU hash
    uint32_t    symoffset;
    ElfW(Addr) *bloom;
    uint32_t    bloom_sz;
    uint32_t    bloom_shift;
    
    int         is_use_rela;
    int         is_use_gnu_hash;
} re_elf_t;

#ifdef __cplusplus
}
#endif

#endif //RE_ELF_H
