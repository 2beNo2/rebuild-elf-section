#include <string.h>
#include <stdio.h>
#include "re_elf.h"

#define RE_DEBUG 1


//ELF header checker
int re_elf_check_elfheader(uintptr_t base_addr){
    ElfW(Ehdr) *ehdr = (ElfW(Ehdr)*)base_addr;

    //check magic
    if(0 != memcmp(ehdr->e_ident, ELFMAG, SELFMAG)) return -1;

    //check class (64/32) 得删除，不该这样判断
#if defined(__LP64__)
    if(ELFCLASS64 != ehdr->e_ident[EI_CLASS]) return -1;
#else
    if(ELFCLASS32 != ehdr->e_ident[EI_CLASS]) return -1;
#endif

    //check endian (little/big)
    if(ELFDATA2LSB != ehdr->e_ident[EI_DATA]) return -1;

    //check version
    if(EV_CURRENT != ehdr->e_ident[EI_VERSION]) return -1;

    //check type
    if(ET_EXEC != ehdr->e_type && ET_DYN != ehdr->e_type) return -1;

    //check machine
#if defined(__arm__)
    if(EM_ARM != ehdr->e_machine) return -1;
#elif defined(__aarch64__)
    if(EM_AARCH64 != ehdr->e_machine) return -1;
#elif defined(__i386__)
    if(EM_386 != ehdr->e_machine) return -1;
#elif defined(__x86_64__)
    if(EM_X86_64 != ehdr->e_machine) return -1;
#else
    return -1;
#endif

    //check version
    if(EV_CURRENT != ehdr->e_version) return -1;
    return 0;
}


static void re_elf_show_elf_info(re_elf_t *self){
    printf("\r\n");
    printf("-------------------------------\r\n");
    printf("pathname:%s\r\n", self->pathname);

    printf("preinit_array_addr: 0x%x\r\n", self->preinit_array_addr);
    printf("preinit_array_off:  0x%x\r\n", self->preinit_array_off);
    printf("preinit_array_sz:   0x%x\r\n", self->preinit_array_sz);

    printf("init_array_addr:    0x%x\r\n", self->init_array_addr);
    printf("init_array_off:     0x%x\r\n", self->init_array_off);
    printf("init_array_sz:      0x%x\r\n", self->init_array_sz);

    printf("finit_array_addr:   0x%x\r\n", self->finit_array_addr);
    printf("finit_array_off:    0x%x\r\n", self->finit_array_off);
    printf("finit_array_sz:     0x%x\r\n", self->finit_array_sz);

    printf("hash_addr:          0x%x\r\n", self->hash_addr);
    printf("hash_off:           0x%x\r\n", self->hash_off);
    printf("hash_sz:            0x%x\r\n", self->hash_sz);

    printf("dynstr_addr:        0x%x\r\n", self->dynstr_addr);
    printf("dynstr_off:         0x%x\r\n", self->dynstr_off);
    printf("dynstr_sz:          0x%x\r\n", self->dynstr_sz);
    printf("dynsym_addr:        0x%x\r\n", self->dynsym_addr);
    printf("dynsym_off:         0x%x\r\n", self->dynsym_off);
    printf("dynsym_sz:          0x%x\r\n", self->dynsym_sz);

    printf("relplt_addr:        0x%x\r\n", self->relplt_addr);
    printf("relplt_off:         0x%x\r\n", self->relplt_off);
    printf("relplt_sz:          0x%x\r\n", self->relplt_sz);
    printf("reldyn_addr:        0x%x\r\n", self->reldyn_addr);
    printf("reldyn_off:         0x%x\r\n", self->reldyn_off);
    printf("reldyn_sz:          0x%x\r\n", self->reldyn_sz);

    printf("plt_addr:           0x%x\r\n", self->plt_addr);
    printf("plt_off:            0x%x\r\n", self->plt_off);
    printf("plt_sz:             0x%x\r\n", self->plt_sz);
    printf("got_addr:           0x%x\r\n", self->got_addr);
    printf("got_off:            0x%x\r\n", self->got_off);
    printf("got_sz:             0x%x\r\n", self->got_sz);

    printf("text_addr:          0x%x\r\n", self->text_addr);
    printf("text_off:           0x%x\r\n", self->text_off);
    printf("text_sz:            0x%x\r\n", self->text_sz);

    printf("-------------------------------\r\n");
    printf("\r\n");
}


static ElfW(Phdr) *re_elf_get_segment_by_type(re_elf_t *self, ElfW(Word) type){
    ElfW(Phdr) *phdr = NULL;
    for(phdr = self->phdr; phdr < self->phdr + self->ehdr->e_phnum; phdr++){
        if(phdr->p_type == type){
            return phdr;
        }
    }
    return NULL;
}


static ElfW(Off) re_elf_get_section_off(re_elf_t *self, ElfW(Addr) addr){
    ElfW(Phdr) *phdr = NULL;
    for(phdr = self->phdr; phdr < self->phdr + self->ehdr->e_phnum; phdr++){
        if(phdr->p_type == PT_LOAD){
            if(addr >= phdr->p_vaddr && addr < (phdr->p_vaddr + phdr->p_filesz)){
                return (ElfW(Off))(addr - phdr->p_vaddr + phdr->p_offset);
            }
        }
    }
    return (ElfW(Off))addr;
}


int re_elf_init(re_elf_t *self, uintptr_t base_addr, const char *pathname){
    ElfW(Phdr) *dynamic_Phdr  = NULL;
    ElfW(Phdr) *eh_frame_Phdr = NULL;
    ElfW(Dyn)  *dyn           = NULL;
    ElfW(Dyn)  *dyn_end       = NULL;
    uint32_t   *hash          = NULL;

    if(0 == base_addr || NULL == pathname) {
        return -1;
    }
    
    memset(self, 0, sizeof(re_elf_t));

    self->pathname    = pathname;
    self->base_addr   = (ElfW(Addr))base_addr;
    self->ehdr        = (ElfW(Ehdr)*)base_addr;
    self->phdr        = (ElfW(Phdr)*)(base_addr + self->ehdr->e_phoff);

    dynamic_Phdr = re_elf_get_segment_by_type(self, PT_DYNAMIC);
    if(NULL == dynamic_Phdr){
        return -1;
    }
    self->dynamic_tab = (ElfW(Dyn)*)(base_addr + dynamic_Phdr->p_offset);
    self->dynamic_sz  = dynamic_Phdr->p_filesz;
    dyn     = self->dynamic_tab;
    dyn_end = self->dynamic_tab + (self->dynamic_sz / sizeof(ElfW(Dyn)));
    
    for(; dyn < dyn_end; dyn++){
        switch(dyn->d_tag)
        {
        case DT_NULL:
            {
                dyn = dyn_end;
                break;
            }
        case DT_PREINIT_ARRAY:
            {
                self->preinit_array_addr = dyn->d_un.d_ptr;
                self->preinit_array_off  = re_elf_get_section_off(self, self->preinit_array_addr);
                break;
            }
        case DT_PREINIT_ARRAYSZ:
            {
                self->preinit_array_sz = dyn->d_un.d_val;
                break;
            }
        case DT_INIT_ARRAY:
            {
                self->init_array_addr = dyn->d_un.d_ptr;
                self->init_array_off  = re_elf_get_section_off(self, self->init_array_addr);
                break;
            }
        case DT_INIT_ARRAYSZ:
            {
                self->init_array_sz = dyn->d_un.d_val;
                break;
            }
        case DT_FINI_ARRAY:
            {
                self->finit_array_addr = dyn->d_un.d_ptr;
                self->finit_array_off  = re_elf_get_section_off(self, self->finit_array_addr);
                break;
            }
        case DT_FINI_ARRAYSZ:
            {
                self->finit_array_sz = dyn->d_un.d_val;
                break;
            }
        case DT_HASH:
            {
                self->hash_addr = dyn->d_un.d_ptr;
                self->hash_off  = re_elf_get_section_off(self, self->hash_addr);

                hash = (uint32_t *)(self->hash_addr + self->base_addr);
                self->hash_sz = (hash[0] + hash[1]) * 4 + 8;
                if(0 != self->dynsym_ent){
                    self->dynsym_sz = hash[1] * self->dynsym_ent;
                }
                break;
            }
        case DT_STRTAB:
            {
                self->dynstr_addr = dyn->d_un.d_ptr;
                self->dynstr_off  = re_elf_get_section_off(self, self->dynstr_addr);
                break;
            }
        case DT_STRSZ:
            {
                self->dynstr_sz = dyn->d_un.d_val;
                break;
            }
        case DT_SYMTAB:
            {
                self->dynsym_addr = dyn->d_un.d_ptr;
                self->dynsym_off  = re_elf_get_section_off(self, self->dynsym_addr);
                break;
            }
        case DT_SYMENT:
            {
                self->dynsym_ent = dyn->d_un.d_val;
                if(0 != self->hash_sz){
                    self->dynsym_sz = hash[1] * self->dynsym_ent;
                }
                break;
            }
        case DT_PLTREL:
            {
                //use rel or rela?
                self->is_use_rela = (dyn->d_un.d_val == DT_RELA ? 1 : 0);
                break;
            }
        case DT_JMPREL:
            {
                self->relplt_addr = dyn->d_un.d_ptr;
                self->relplt_off  = re_elf_get_section_off(self, self->relplt_addr);
                break;
            }
        case DT_PLTRELSZ:
            {
                self->relplt_sz = dyn->d_un.d_val;
                if(-1 != self->is_use_rela){

                }
                break;
            }
        case DT_REL:
        case DT_RELA:
            {
                self->reldyn_addr = dyn->d_un.d_ptr;
                self->reldyn_off  = re_elf_get_section_off(self, self->reldyn_addr);
                break;
            }
        case DT_RELSZ:
        case DT_RELASZ:
            {
                self->reldyn_sz = dyn->d_un.d_val;
                break;
            }
        case DT_PLTGOT:
            {
                self->got_addr = dyn->d_un.d_ptr;
                self->got_off  = re_elf_get_section_off(self, self->got_addr);
                break;
            }
        default:
            break;
        }
    }
    
    // get .got size
    if(EM_AARCH64 == self->ehdr->e_machine){
        if(1 == self->is_use_rela){
            self->got_sz = 24 + 8 * (self->relplt_sz) / sizeof(Elf64_Rela);
        }else{
            self->got_sz = 24 + 8 * (self->relplt_sz) / sizeof(Elf64_Rel);
        }
    }else{
        if(1 == self->is_use_rela){
            self->got_sz = 12 + 4 * (self->relplt_sz) / sizeof(Elf32_Rela);
        }else{
            self->got_sz = 12 + 4 * (self->relplt_sz) / sizeof(Elf32_Rel);
        }
    }

    // get .plt
    if(EM_AARCH64 == self->ehdr->e_machine){
        self->plt_addr = self->relplt_addr + self->relplt_sz + 8;
        if(1 == self->is_use_rela){
            self->plt_sz = 32 + 16 * (self->relplt_sz) / sizeof(Elf64_Rela);
        }else{
            self->plt_sz = 32 + 16 * (self->relplt_sz) / sizeof(Elf64_Rel);
        }
    }else{
        self->plt_addr = self->relplt_addr + self->relplt_sz;
        if(1 == self->is_use_rela){
            self->plt_sz = 20 + 12 * (self->relplt_sz) / sizeof(Elf32_Rela);
        }else{
            self->plt_sz = 20 + 12 * (self->relplt_sz) / sizeof(Elf32_Rel);
        }
    }
    self->plt_off = re_elf_get_section_off(self, self->plt_addr);

    // get .text
    self->text_addr = self->plt_addr + self->plt_sz;
    self->text_off  = re_elf_get_section_off(self, self->text_addr);
    if(EM_AARCH64 == self->ehdr->e_machine){
        eh_frame_Phdr = re_elf_get_segment_by_type(self, PT_GNU_EH_FRAME);
    }else{
        eh_frame_Phdr = re_elf_get_segment_by_type(self, PT_SHT_ARM_EXIDX);
    }
    if(NULL == eh_frame_Phdr){
        return -1;
    }
    self->text_sz = eh_frame_Phdr->p_vaddr - self->text_addr;


#ifdef RE_DEBUG
    re_elf_show_elf_info(self);
#endif

    return 0;
}


int re_elf_rewrite(re_elf_t *self, uintptr_t base_addr){

}