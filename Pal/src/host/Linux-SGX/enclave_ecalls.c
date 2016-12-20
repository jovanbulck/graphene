/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include "pal_linux.h"
#include "pal_security.h"
#include <api.h>

#include "ecall_types.h"

#define SGX_CAST(type, item) ((type) (item))

extern void * enclave_base, * enclave_top;

void pal_linux_main (const char ** arguments, const char ** environments,
                     struct pal_sec * sec_info);

int enclave_ecall_thread_start (void * pms);

/*
 * PoC: asm stub redirects control to this function to allow debugging..
 */
int enclave_handle_ecall(void * pms, void (*fct)(void))
{
    if (fct == &enclave_ecall_thread_start)
    {
        char *str = "passing thread_start\n\n";
        ocall_print_string(str, strlen(str));
        
        return enclave_ecall_thread_start(pms);
    }

    char *str = "enclave_handle_ecall: asm stub passed function pointer:\n";
    ocall_print_string(str, strlen(str));
    ocall_dump(fct);
    fct();
    
    ocall_exit();
}

int enclave_ecall_pal_main (void * pms)
{
    ms_ecall_pal_main_t * ms = SGX_CAST(ms_ecall_pal_main_t *, pms);

    if (!pms) return -PAL_ERROR_INVAL;

    enclave_base = ms->ms_enclave_base;
    enclave_top = ms->ms_enclave_base + ms->ms_enclave_size;

    pal_linux_main(ms->ms_arguments,
                   ms->ms_environments,
                   ms->ms_sec_info);

    ocall_exit();
    return 0;
}

/*
 * PoC: this function represents sensitive intra-enclave code that should not
 * be called directly from the untrusted runtime..
 */
void enclave_private_func(void * arg)
{
    char *str = "[trts] enclave_private_func: should *not* see this; exiting..\n";
    ocall_print_string(str, strlen(str));
    ocall_exit_process(-1);
}

int enclave_ecall_thread_start (void * pms)
{
    ms_ecall_thread_start_t * ms = SGX_CAST(ms_ecall_thread_start_t *, pms);

    if (!pms) return -PAL_ERROR_INVAL;

    if (ms->ms_child_tid)
        *ms->ms_child_tid = ms->ms_tid;

    //XXX the ms->ms_func is provided by the untrusted runtime, but should
    // be verified to be a valid entry point to prevent code abuse attacks..
    ms->ms_func(ms->ms_arg);
    
    ocall_exit();
    return 0;
}

void * ecall_table[ECALL_NR] = {
        [ECALL_PAL_MAIN]        = (void *) enclave_ecall_pal_main,
        [ECALL_THREAD_START]    = (void *) enclave_ecall_thread_start,
    };
