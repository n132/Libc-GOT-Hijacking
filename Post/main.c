#include<stdio.h>
int main(){
    size_t addr = 0;
    size_t len = 0;
    printf("%p\n",printf);
    read(0,&addr,8);
    read(0,&len,8);
    read(0,addr,len);
    printf("n132");
} 