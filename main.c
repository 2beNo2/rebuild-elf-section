
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include "utils/ch_elf.h"

int rebuild(const char* pathname){
    FILE *fp = NULL;
    char magic[5] = {0};

    fp = fopen(pathname, "rb+");
    if(NULL == fp){
        return -1;
    }
    
    /*
    FILE *file = NULL;
    file = fopen(szFileFullPath,"rb");
    if ( !file )
        return;
    fseek(file,0,SEEK_END);
    int nFileLen = ftell(file);
    fseek(file,0,SEEK_SET);
    fclose(file);
    */

    fread(magic, 1, 5, fp);
    printf("%s\n", magic);

    fclose(fp);
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


