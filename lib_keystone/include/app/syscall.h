//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef __SYSCALL_H__
#define __SYSCALL_H__

#include <stddef.h>
#include <stdint.h>
#include "sealing.h"

#include "shared/eyrie_call.h"

#define SYSCALL(which, arg0, arg1, arg2, arg3, arg4)           \
  ({                                                           \
    register uintptr_t a0 asm("a0") = (uintptr_t)(arg0);       \
    register uintptr_t a1 asm("a1") = (uintptr_t)(arg1);       \
    register uintptr_t a2 asm("a2") = (uintptr_t)(arg2);       \
    register uintptr_t a3 asm("a3") = (uintptr_t)(arg3);       \
    register uintptr_t a4 asm("a4") = (uintptr_t)(arg4);       \
    register uintptr_t a7 asm("a7") = (uintptr_t)(which);      \
    asm volatile("ecall"                                       \
                 : "+r"(a0)                                    \
                 : "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a7) \
                 : "memory");                                  \
    a0;                                                        \
  })

#define SYSCALL_0(which) SYSCALL(which, 0, 0, 0, 0, 0)
#define SYSCALL_1(which, arg0) SYSCALL(which, arg0, 0, 0, 0, 0)
#define SYSCALL_2(which, arg0, arg1) SYSCALL(which, arg0, arg1, 0, 0, 0)
#define SYSCALL_3(which, arg0, arg1, arg2) \
  SYSCALL(which, arg0, arg1, arg2, 0, 0)
#define SYSCALL_4(which, arg0, arg1, arg2, arg3) \
  SYSCALL(which, arg0, arg1, arg2, arg3, 0)
#define SYSCALL_5(which, arg0, arg1, arg2, arg3, arg4) \
  SYSCALL(which, arg0, arg1, arg2, arg3, arg4)

int
copy_from_shared(void* dst, uintptr_t offset, size_t data_len);

int
ocall(
    unsigned long call_id, void* data, size_t data_len, void* return_buffer,
    size_t return_len);
uintptr_t
untrusted_mmap();
int
attest_enclave(void* report, void* data, size_t size);

int
m_enclave_create_group(void* identity, size_t size);

int
s_enclave_join_group(void* identity, size_t size);

int
slave_enclave_set_dataptr(void* src, size_t size, size_t numbers);

int
main_enclave_get_slave_enclave_data(void* dest, size_t size, size_t numbers);

int
slave_enclave_set_dataptr_yx(void* src);

int
main_enclave_get_slave_enclave_data_yx(void* dest);

int
main_enclave_get_numberblock(void* dest, size_t set_number, size_t size);

int
slave_enclave_set_numberblock(void* src, size_t set_number, size_t size);

int
other_enclave_access_stm_test();

int
other_enclave_access_epm_test_o(void* flag);

int
other_enclave_access_epm_test_s(void* flag);

int
m_attestt_s_enclave(size_t slave_id, size_t flexible);

int
s_enclave_attestted(size_t slave_id, size_t flexible);

int
wait_main_dispatch(void* dest, void* block_id, void* block_size, uint64_t slave_id, uint64_t flexible);

int
main_dispatch_send(void* src, uint64_t block_id, uint64_t block_size, uint64_t slave_id, uint64_t flexible);

int
slave_set_block(void* src, uint64_t block_id, uint64_t block_size, uint64_t slave_id, uint64_t flexible);

int
get_slave_block(void* dest, uint64_t block_id, uint64_t block_size, uint64_t slave_id, uint64_t flexible);

int
get_sealing_key(
    struct sealing_key* sealing_key_struct, size_t sealing_key_struct_size,
    void* key_ident, size_t key_ident_size);

#endif /* syscall.h */
