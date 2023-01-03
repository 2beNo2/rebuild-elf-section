#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include<string.h>

#include "re_elf.h"


int rebuild(const char* pathname)
{
    FILE *fp = NULL;
    uint32_t file_sz = 0;
    char* file_buf = NULL;
    re_elf_t re_self;

    fp = fopen(pathname, "rb+");
    if(NULL == fp){
        printf("[-] fopen:[%s], errno:[%s]", pathname, strerror(errno));
        return -1;
    }
    fseek(fp, 0, SEEK_END);
    file_sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    file_buf = (char*)malloc(file_sz);
    if(NULL == file_buf){
        printf("[-] malloc failed, errno:[%s]", strerror(errno));
        fclose(fp);
        return -1;
    }
    fread(file_buf, 1, file_sz, fp);
    fclose(fp);

    // start rebuild
    if(re_elf_check_elfheader((uintptr_t)file_buf) < 0){
        printf("[-] error elf format!\n");
        free(file_buf);
        return -1;
    }

    if(re_elf_init(&re_self, (uintptr_t)file_buf, pathname, file_sz) < 0){
        printf("[-] elf init failed!\n");
        free(file_buf);
        return -1;
    }

    if(re_elf_rewrite(&re_self) < 0){
        printf("[-] elf rewrite failed!\n");
        free(file_buf);
        re_elf_destructor(&re_self);
        return -1;
    }

    free(file_buf);
    re_elf_destructor(&re_self);

    return 0;
}
