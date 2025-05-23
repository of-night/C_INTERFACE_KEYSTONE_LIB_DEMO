#ifndef __EYRIE_CALL_H__
#define __EYRIE_CALL_H__

#define RUNTIME_SYSCALL_UNKNOWN             1000
#define RUNTIME_SYSCALL_OCALL               1001
#define RUNTIME_SYSCALL_SHAREDCOPY          1002
#define RUNTIME_SYSCALL_ATTEST_ENCLAVE      1003
#define RUNTIME_SYSCALL_GET_SEALING_KEY     1004
#define RUNTIME_SYSCALL_MAIN_ENCLAVE_GET_SLAVE_ENCLAVE_DATA 1005
#define RUNTIME_SYSCALL_SLAVE_ENCLAVE_SET_DATAPTR           1006
#define RUNTIME_SYSCALL_CREATE_GROUP                        1007
#define RUNTIME_SYSCALL_JOIN_GROUP                          1008
#define RUNTIME_SYSCALL_YXSTM_SET_NUMBERBLOCK               1009
#define RUNTIME_SYSCALL_YXSTM_GET_NUMBERBLOCK               1010
#define RUNTIME_SYSCALL_STM_ACCESS_TEST                     1011
#define RUNTIME_SYSCALL_TEST_OTHER_ENCLAVE_ACCESS_EPM_O     1012
#define RUNTIME_SYSCALL_TEST_OTHER_ENCLAVE_ACCESS_EPM_S     1013
#define RUNTIME_SYSCALL_M_ATTEST_S_ENCLAVE                  1014
#define RUNTIME_SYSCALL_S_ENCLAVE_ATTESTTED                 1015
#define RUNTIME_SYSCALL_WAIT_MAIN_DISPATCH                  1016
#define RUNTIME_SYSCALL_MAIN_DISPATCH_SEND                  1017
#define RUNTIME_SYSCALL_SLAVE_SET_BLOCK                     1018
#define RUNTIME_SYSCALL_GET_SLAVE_BLOCK                     1019
#define RUNTIME_SYSCALL_EXIT                1101

#endif  // __EYRIE_CALL_H__
