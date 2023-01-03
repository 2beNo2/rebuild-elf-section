#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "utils/re_rebuild.h"


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
            // rebuild
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


