#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include "utils/re_elf.h"

int rebuild(const char* pathname){
    FILE *fp = NULL;
    int nFileSize = 0;
    char* pFileBuffer = NULL;

    fp = fopen(pathname, "rb+");
    if(NULL == fp){
        return -1;
    }
    fseek(fp, 0, SEEK_END);
    nFileSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    pFileBuffer = (char*)malloc(nFileSize);
    if(NULL == pFileBuffer){
        fclose(fp);
        return -1;
    }

    fread(pFileBuffer, 1, nFileSize, fp);
    fclose(fp);
    // printf("%s\n", pFileBuffer);

    free(pFileBuffer);
    return 1;
}


int main(int argc, char* argv[]){
    int c = 0;
    if(argc < 3){
        printf("Usage:%s -r pathname\n", argv[0]);
        return 0;
    }

    while((c = getopt(argc, argv, "r:")) != -1) {
      switch(c) {
        case 'r': {
            printf("start rebuilding %s...\n", optarg);
            if(rebuild(optarg) < 0){
                printf("rebuild failed!\n");
            }else{
                printf("rebuild success!\n");
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


