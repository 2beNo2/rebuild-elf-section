#include <string.h>

#include "re_elf.h"


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


static ElfW(Phdr) *re_elf_get_segment_by_type(re_elf_t *self, ElfW(Word) type){
    ElfW(Phdr) *phdr = NULL;
    for(phdr = self->phdr; phdr < self->phdr + self->ehdr->e_phnum; phdr++){
        if(phdr->p_type == type){
            return phdr;
        }
    }
    return NULL;
}


int re_elf_init(re_elf_t *self, uintptr_t base_addr, const char *pathname){
    ElfW(Phdr) *dhdr = NULL;
    ElfW(Phdr) *eh_frame = NULL;

    if(0 == base_addr || NULL == pathname) {
        return -1;
    }

    memset(self, 0, sizeof(re_elf_t));

    self->pathname = pathname;
    self->base_addr = (ElfW(Addr))base_addr;
    self->ehdr = (ElfW(Ehdr)*)base_addr;
    self->phdr = (ElfW(Phdr)*)(base_addr + self->ehdr->e_phoff);

    dhdr = re_elf_get_segment_by_type(self, PT_DYNAMIC);
    if(NULL == dhdr){
        return -1;
    }
    self->dynamic_tab = (ElfW(Dyn)*)(base_addr + dhdr->p_offset);
    self->dynamic_sz = dhdr->p_filesz;

    ElfW(Dyn) *dyn     = self->dynamic_tab;
    ElfW(Dyn) *dyn_end = self->dynamic_tab + (self->dynamic_sz / sizeof(ElfW(Dyn)));
    uint32_t  *hash;

    for(; dyn < dyn_end; dyn++){
        switch(dyn->d_tag)
        {
        case DT_NULL:
            //the end of the dynamic-section
            dyn = dyn_end;
            break;
        case DT_PREINIT_ARRAY:
            {
                self->preinit_array_tab = self->base_addr + dyn->d_un.d_ptr;
                break;
            }
        case DT_PREINIT_ARRAYSZ:
            {
                self->preinit_array_sz = dyn->d_un.d_val;
                break;
            }
        case DT_INIT_ARRAY:
            {
                self->init_array_tab = self->base_addr + dyn->d_un.d_ptr;
                break;
            }
        case DT_INIT_ARRAYSZ:
            {
                self->init_array_sz = dyn->d_un.d_val;
                break;
            }
        case DT_FINI_ARRAY:
            {
                self->finit_array_tab = self->base_addr + dyn->d_un.d_ptr;
                break;
            }
        case DT_FINI_ARRAYSZ:
            {
                self->finit_array_sz = dyn->d_un.d_val;
                break;
            }
        case DT_HASH:
            {
                self->hash_tab = self->base_addr + dyn->d_un.d_ptr;
                hash = (uint32_t *)self->hash_tab;
                self->hash_sz = (hash[0] + hash[1]) * 4 + 8;
                if(0 != self->dynsym_ent){
                    self->dynsym_sz = hash[1] * self->dynsym_ent;
                }
                break;
            }
        case DT_STRTAB:
            {
                self->dynstr_tab = self->base_addr + dyn->d_un.d_ptr;
                break;
            }
        case DT_STRSZ:
            {
                self->dynstr_sz = dyn->d_un.d_val;
                break;
            }
        case DT_SYMTAB:
            {
                self->dynsym_tab = (ElfW(Sym)*)(self->base_addr + dyn->d_un.d_ptr);
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
                self->relplt_tab = (ElfW(Addr))(self->base_addr + dyn->d_un.d_ptr);
                break;
            }
        case DT_PLTRELSZ:
            {
                self->relplt_sz = dyn->d_un.d_val;
                break;
            }
        case DT_REL:
        case DT_RELA:
            {
                self->reldyn_tab = (ElfW(Addr))(self->base_addr + dyn->d_un.d_ptr);
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
                self->got_tab = (ElfW(Addr))(self->base_addr + dyn->d_un.d_ptr);
                if(ELFCLASS64 == self->ehdr->e_ident[EI_CLASS]){
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
                break;
            }
        default:
            break;
        }
    }

    // get .plt
    if(ELFCLASS64 == self->ehdr->e_ident[EI_CLASS]){
        self->plt_tab = self->relplt_tab + self->relplt_sz + 8;
        if(1 == self->is_use_rela){
            self->plt_sz = 32 + 16 * (self->relplt_sz) / sizeof(Elf64_Rela);
        }else{
            self->plt_sz = 32 + 16 * (self->relplt_sz) / sizeof(Elf64_Rel);
        }
    }else{
        self->plt_tab = self->relplt_tab + self->relplt_sz;
        if(1 == self->is_use_rela){
            self->plt_sz = 20 + 12 * (self->relplt_sz) / sizeof(Elf32_Rela);
        }else{
            self->plt_sz = 20 + 12 * (self->relplt_sz) / sizeof(Elf32_Rel);
        }
    }

    // get .text
    self->text_tab = self->plt_tab + self->plt_sz;
    if(ELFCLASS64 == self->ehdr->e_ident[EI_CLASS]){
        eh_frame = re_elf_get_segment_by_type(self, PT_GNU_EH_FRAME);
    }else{
        eh_frame = re_elf_get_segment_by_type(self, PT_SHT_ARM_EXIDX);
    }
    if(NULL == eh_frame){
        return -1;
    }
    self->text_sz = eh_frame->p_paddr - self->text_tab - self->base_addr;

    return 0;
}
