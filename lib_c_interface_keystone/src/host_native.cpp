#include <edge_call.h>
#include <keystone.h>
#include "ipfs_keystone.h"
#include <iostream>

char* ADDFILENAME = NULL;

unsigned long
print_string(char* str);
void
print_string_wrapper(void* buffer);
void
get_filename_wrapper(void* buffer);

#define OCALL_PRINT_STRING 1
#define OCALL_GET_FILENAME 2


static size_t temp_strlen(char* str) {
  size_t len = 0;
  while (*str != '\0') {
    str++;
    len++;
  }

  return len;
}

void ipfs_keystone(int isAES, char* fileName) {
  std::cout << "v0.0.1 test" << std::endl;

  // 需要分配内存并复制字符串，确保释放内存以避免内存泄漏。
  if (fileName != NULL) {

    if (ADDFILENAME != NULL) {

      delete[] ADDFILENAME; // 释放之前分配的内存（如果有的话）
    }
    ADDFILENAME = new char[strlen(fileName) + 1]; // 分配足够的空间
    memcpy(ADDFILENAME, fileName, strlen(fileName) + 1); // 复制字符串
  }

  std::cout << "add file name: " << ADDFILENAME << std::endl;

  Keystone::Enclave enclave;
  Keystone::Params params;

  params.setFreeMemSize(1024 * 1024);
  params.setUntrustedSize(1024 * 1024);

  switch (isAES)
  {
  case AES:
      enclave.init("aes", "eyrie-rt", "loader.bin", params);
      break;
  case SM4:
      enclave.init("sm4", "eyrie-rt", "loader.bin", params);
      break;
  case demo:
      enclave.init("hello-native", "eyrie-rt", "loader.bin", params);
      break;
  default:
      std::cout << "TEE do nothing" << std::endl;
      return;
  }

  enclave.registerOcallDispatch(incoming_call_dispatch);

  /* We must specifically register functions we want to export to the
     enclave. */
  register_call(OCALL_PRINT_STRING, print_string_wrapper);
  register_call(OCALL_GET_FILENAME, get_filename_wrapper);

  edge_call_init_internals(
      (uintptr_t)enclave.getSharedBuffer(), enclave.getSharedBufferSize());

  enclave.run();

  if (ADDFILENAME != NULL) {
        delete[] ADDFILENAME;
        ADDFILENAME = NULL;
  }
  std::cout << "enclave done" << std::endl;
}


/***
 * An example call that will be exposed to the enclave application as
 * an "ocall". This is performed by an edge_wrapper function (below,
 * print_string_wrapper) and by registering that wrapper with the
 * enclave object (below, main).
 ***/
unsigned long
print_string(char* str) {
  return printf("Enclave said: \"%s\"\n", str);
}


/***
 * Example edge-wrapper function. These are currently hand-written
 * wrappers, but will have autogeneration tools in the future.
 ***/
void
print_string_wrapper(void* buffer) {
  /* Parse and validate the incoming call data */
  struct edge_call* edge_call = (struct edge_call*)buffer;
  uintptr_t call_args;
  unsigned long ret_val;
  size_t arg_len;
  if (edge_call_args_ptr(edge_call, &call_args, &arg_len) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  /* Pass the arguments from the eapp to the exported ocall function */
  ret_val = print_string((char*)call_args);

  /* Setup return data from the ocall function */
  uintptr_t data_section = edge_call_data_ptr();
  memcpy((void*)data_section, &ret_val, sizeof(unsigned long));
  if (edge_call_setup_ret(
          edge_call, (void*)data_section, sizeof(unsigned long))) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  } else {
    edge_call->return_data.call_status = CALL_STATUS_OK;
  }

  /* This will now eventually return control to the enclave */
  return;
}

void
get_filename_wrapper(void* buffer) {

  struct edge_call* edge_call = (struct edge_call*)buffer;
  uintptr_t call_args;
  size_t arg_len;
  if (edge_call_args_ptr(edge_call, &call_args, &arg_len) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  if (ADDFILENAME == NULL) {
    return;
  }

  if (edge_call_setup_ret(edge_call, (void*)ADDFILENAME, strlen(ADDFILENAME) + 1)) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  } else {
    edge_call->return_data.call_status = CALL_STATUS_OK;
  }

  if (ADDFILENAME != NULL) {
    delete[] ADDFILENAME;
    ADDFILENAME = NULL;
  }
  
  return;

}

