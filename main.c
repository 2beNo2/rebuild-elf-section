#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include "utils/re_elf.h"

int rebuild(const char* pathname)
{
    FILE *fp = NULL;
    uint32_t file_sz = 0;
    char* file_buf = NULL;
    re_elf_t re_self;

    fp = fopen(pathname, "rb+");
    if(NULL == fp){
        return -1;
    }
    fseek(fp, 0, SEEK_END);
    file_sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    file_buf = (char*)malloc(file_sz);
    if(NULL == file_buf){
        fclose(fp);
        return -1;
    }
    fread(file_buf, 1, file_sz, fp);
    fclose(fp);
    //printf("%s\n", file_buf);

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
    return 1;
}


int main(int argc, char* argv[])
{
    int c = 0;
    if(argc < 3){
        printf("Usage:%s -r pathname\n", argv[0]);
        return 0;
    }

    while((c = getopt(argc, argv, "r:")) != -1) {
      switch(c) {
        case 'r': {
            printf("[+] start rebuilding %s\n", optarg);
            if(rebuild(optarg) < 0){
                printf("[-] rebuild failed!\n");
            }else{
                printf("[+] rebuild success!\n");
            }
            break;
        }
        case '?': {
            printf("Usage:%s -r pathname\n", argv[0]);
            break;
        }
      }
    }
    return 0;
}


