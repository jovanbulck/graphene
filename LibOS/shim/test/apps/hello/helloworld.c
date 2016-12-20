/*
 * Elementary dummy application that features a struct with 2 function pointers,
 * and decides access by comparing a user-provided number with a secret PIN.
 */
#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>

/*
 * Simply retrieve the PIN from the untrusted runtime (ignore secure I/O).
 */
int get_user_pin(void)
{
    int pin = 0x0;
    printf("app: enter PIN..\n> ");
    fflush(stdout);
    scanf("%d", &pin);
    return pin;
}

void access_allowed_handler(void)
{
    puts("===> app: access allowed! <===");
    exit(0);
}   

void access_denied_handler(void)
{
    puts("===> app: access denied! <===");
}

struct accessControl {
    int secretPin;
    void (*allowAccess)(void);
    void (*denyAccess)(void);
};

struct accessControl ac = {
    .secretPin = 1234,
    .allowAccess = &access_allowed_handler,
    .denyAccess = &access_denied_handler
};

int main(int argc, char ** argv)
{
    printf("\n\nHello world from enclaved application binary!\n");
    printf("\t--> ac.allowAccess at %p is %p (access_allowed_handler)\n",
        &ac.allowAccess, ac.allowAccess);

    int pin = get_user_pin();
    printf("user entered %d\n", pin);
    
    puts("app: checking acess..");
    if (pin == ac.secretPin) ac.allowAccess(); else ac.denyAccess();

    /*
     * Untrusted runtime can use the following ocall to recognize the enclaved
     * binary is running, so the ecall attack can be launched.
     */
    puts("app: opening dummy_file");
    fflush(stdout);
    int fd = open("dummy_file", O_RDWR);
    printf("\n\napp: should never see this (fd=%d)\n", fd);
   
    return 0;
}
