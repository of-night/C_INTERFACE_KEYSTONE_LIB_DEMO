#include <edge_call.h>
#include <keystone.h>
#include "ipfs_keystone.h"
#include <iostream>
#include <chrono>

char* ADDFILENAME = NULL;
RingBuffer* tempRB = NULL;

unsigned long
print_string(char* str);
void
print_string_wrapper(void* buffer);
void
get_filename_wrapper(void* buffer);
int ring_buffer_write(RingBuffer *rb, const char *data, size_t length);
void
ring_buffer_write_wrapper(void* buffer);
void
ring_buffer_read_wrapper(void* buffer);

#define OCALL_PRINT_STRING 1
#define OCALL_GET_FILENAME 2
#define OCALL_RING_BUFFER_WRITE 3
#define OCALL_RING_BUFFER_READ 4


void ipfs_keystone(int isAES, void* fileName, void* rb) {

  // 需要分配内存并复制字符串，确保释放内存以避免内存泄漏。
  if (fileName != NULL) {

    ADDFILENAME = (char*)fileName;
    // if (ADDFILENAME != NULL) {

    //   delete[] ADDFILENAME; // 释放之前分配的内存（如果有的话）
    // }
    // ADDFILENAME = new char[strlen(fileName) + 1]; // 分配足够的空间
    // memcpy(ADDFILENAME, fileName, strlen(fileName) + 1); // 复制字符串
  }

  if (rb != NULL)
  {
    tempRB = (RingBuffer*)rb;
  }

  // 获取当前时间点
  auto start = std::chrono::steady_clock::now();

  Keystone::Enclave enclave;
  Keystone::Params params;

  params.setFreeMemSize(256 * 1024 * 1024);
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
  register_call(OCALL_RING_BUFFER_WRITE, ring_buffer_write_wrapper);

  edge_call_init_internals(
      (uintptr_t)enclave.getSharedBuffer(), enclave.getSharedBufferSize());

  auto end = std::chrono::steady_clock::now();
  std::chrono::duration<double, std::micro> elapsed = end - start;
  std::cout << "Elapsed time: " << elapsed.count() << " microseconds" << std::endl;
  enclave.run();

  tempRB->running = 0;

  ADDFILENAME = NULL;

  std::cout << "enclave done" << std::endl;
}

void ipfs_keystone_de(int isDeAES, void* fileName, void* rb) {

  // 需要分配内存并复制字符串，确保释放内存以避免内存泄漏。
  if (fileName != NULL) {

    ADDFILENAME = (char*)fileName;
    // if (ADDFILENAME != NULL) {

    //   delete[] ADDFILENAME; // 释放之前分配的内存（如果有的话）
    // }
    // ADDFILENAME = new char[strlen(fileName) + 1]; // 分配足够的空间
    // memcpy(ADDFILENAME, fileName, strlen(fileName) + 1); // 复制字符串
  }

  if (rb != NULL)
  {
    tempRB = (RingBuffer*)rb;
  }

  // 获取当前时间点
  auto start = std::chrono::steady_clock::now();

  Keystone::Enclave enclave;
  Keystone::Params params;

  params.setFreeMemSize(256 * 1024 * 1024);
  params.setUntrustedSize(1024 * 1024);

  switch (isDeAES)
  {
  case AES:
      enclave.init("deaes", "eyrie-rt", "loader.bin", params);
      break;
  case SM4:
      enclave.init("desm4", "eyrie-rt", "loader.bin", params);
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
  register_call(OCALL_RING_BUFFER_READ, ring_buffer_read_wrapper);

  edge_call_init_internals(
      (uintptr_t)enclave.getSharedBuffer(), enclave.getSharedBufferSize());

  auto end = std::chrono::steady_clock::now();
  std::chrono::duration<double, std::micro> elapsed = end - start;
  std::cout << "Elapsed time: " << elapsed.count() << " microseconds" << std::endl;
  enclave.run();

  // tempRB->running = 0;

  ADDFILENAME = NULL;

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
    std::cout << "ADDFILENAME == NULL in get_filename_wrapper. ADDFILENAME: " << ADDFILENAME << std::endl;
    return;
  }

  if (edge_call_setup_wrapped_ret(edge_call, (void*)ADDFILENAME, strlen(ADDFILENAME) + 1)) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  } else {
    edge_call->return_data.call_status = CALL_STATUS_OK;
  }
  
  return;
}

void
ring_buffer_write_wrapper(void* buffer) {

  struct edge_call* edge_call = (struct edge_call*)buffer;
  uintptr_t call_args;
  size_t arg_len;
  if (edge_call_args_ptr(edge_call, &call_args, &arg_len) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  if (tempRB == NULL)
  {
    std::cout << "tempRB == NULL in ring_buffer_write_wrapper. tempRB: " << tempRB << std::endl;
    return;
  }

  if (arg_len > 0) {
    ring_buffer_write(tempRB, (char *)call_args, arg_len);
  }

  edge_call->return_data.call_status = CALL_STATUS_OK;

  return;
}

void
ring_buffer_read_wrapper(void* buffer) {

  struct edge_call* edge_call = (struct edge_call*)buffer;
  uintptr_t call_args;
  size_t arg_len;
  if (edge_call_args_ptr(edge_call, &call_args, &arg_len) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  if (tempRB == NULL)
  {
    std::cout << "tempRB == NULL in ring_buffer_read_wrapper. tempRB: " << tempRB << std::endl;
    return;
  }

  size_t usedSpace = 0;
  size_t size = 0;
  while (ring_buffer_space_used(tempRB) == 0 && tempRB->running)
  {
    ;
  }

  if (!tempRB->running && ring_buffer_space_used(tempRB) == 0) {
    // free(tempRB);  // 不释放内存空间，只设置为NULL，方便cgo进行最后的判断
    tempRB = NULL;
    if (edge_call_setup_wrapped_ret(edge_call, NULL, 0)) {
      edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
    } else {
      edge_call->return_data.call_status = CALL_STATUS_OK;
    }
    return;
    // size = 0;
  } else {
    usedSpace = ring_buffer_space_used(tempRB);
    size = usedSpace < 786432 ? usedSpace : 786432;
    // std::cout << "size :" << size << std::endl;
    // size = (size + 0xf) & ~0xf;
    // std::cout << "size 1 :" << size << std::endl;
  }

  // char* temp = (char*)malloc(size);
  // int remaining = BUFFER_SIZE - tempRB->read_pos;

  // if (size <= remaining) {
  //   memcpy(temp, tempRB->buffer + tempRB->read_pos, size);
  //   tempRB->read_pos += size;
  // } else {
  //   memcpy(temp, tempRB->buffer + tempRB->read_pos, remaining);
  //   memcpy(temp + remaining, tempRB->buffer, size - remaining);
  //   tempRB->read_pos = size - remaining;
  // }

  // printf("temp %s\n", temp);

  // char* temp = (char*)"(void*)(temp)";

  // if (edge_call_setup_wrapped_ret(edge_call, (void*)(temp), size)) {
  // if (edge_call_setup_wrapped_ret(edge_call, (void*)temp, strlen(temp) + 1)) {
  //   edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  // } else {
  //   edge_call->return_data.call_status = CALL_STATUS_OK;
  // }

  struct edge_data data_wrapper;
  data_wrapper.size = size;
  edge_call_get_offset_from_ptr(
      _shared_start + sizeof(struct edge_call) + sizeof(struct edge_data),
      sizeof(struct edge_data), &data_wrapper.offset);

  int remaining = BUFFER_SIZE - tempRB->read_pos;
  // // printf("ring data p: %s\n", tempRB->buffer + tempRB->read_pos);
  // printf("read wrapper start......\n");
  if (size <= remaining) {
    memcpy(
      (void*)(_shared_start + sizeof(struct edge_call) + sizeof(struct edge_data)),
      (void*)(tempRB->buffer + tempRB->read_pos), size);
      tempRB->read_pos += size;
  } else {
    memcpy(
      (void*)(_shared_start + sizeof(struct edge_call) + sizeof(struct edge_data)),
      (void*)(tempRB->buffer + tempRB->read_pos), remaining);
    memcpy(
      (void*)(_shared_start + sizeof(struct edge_call) + sizeof(struct edge_data) + remaining),
      (void*)(tempRB->buffer), size - remaining);
      tempRB->read_pos = size - remaining;
  }
  // printf("read wrapper end......\n");

  // // printf("utm data p: %s", (void*)(_shared_start + sizeof(struct edge_call) + sizeof(struct edge_data)));

  // // ring_buffer_read(tempRB, (void*)(_shared_start + sizeof(struct edge_call) + sizeof(struct edge_data)), size)
  // // memcpy(
  // //     (void*)(_shared_start + sizeof(struct edge_call) + sizeof(struct edge_data)),
  // //     ptr, size);

  memcpy(
      (void*)(_shared_start + sizeof(struct edge_call)), &data_wrapper,
      sizeof(struct edge_data));

  edge_call->return_data.call_ret_size = sizeof(struct edge_data);
  if (edge_call_get_offset_from_ptr(
      _shared_start + sizeof(struct edge_call), sizeof(struct edge_data),
      &edge_call->return_data.call_ret_offset)) {
        edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  } else {
    edge_call->return_data.call_status = CALL_STATUS_OK;
  }

  // 不能直接用，会超过边界
  // if (edge_call_setup_wrapped_ret(edge_call, (void*)(tempRB->read_pos), (usedSpace < 786432 ? usedSpace : 786432))) {
  //   edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  // } else {
  //   edge_call->return_data.call_status = CALL_STATUS_OK;
  // }

  return;
}

// 初始化环形缓冲区
void init_ring_buffer(RingBuffer *rb) {
    rb->read_pos = 0;
    rb->write_pos = 0;
    rb->running = 1;
}

// 获取缓冲区可用空间大小
int ring_buffer_space_available(RingBuffer *rb) {
  if (rb->write_pos < rb->read_pos)
  {
    return rb->read_pos - rb->write_pos - 1;
  }
  
  return BUFFER_SIZE - (rb->write_pos - rb->read_pos) - 1;
}

// 获取缓冲区已使用空间大小
int ring_buffer_space_used(RingBuffer *rb) {
  if (rb->write_pos < rb->read_pos) return BUFFER_SIZE - rb->read_pos + rb->write_pos;
    return rb->write_pos - rb->read_pos;
}

// 向缓冲区写入数据
int ring_buffer_write(RingBuffer *rb, const char *data, size_t length) {
  // printf("data p: %s\n", data);
    while (ring_buffer_space_available(rb) < length && rb->running) {
        ;
    }
    if (!rb->running) {
        return 0;
    }

    int space = ring_buffer_space_available(rb);
    int written = 0;

    // printf("read ring buffer write start......\n");

    while (length > 0 && space > 0) {
        int chunk = (space < length) ? space : length;
        int remaining = BUFFER_SIZE - rb->write_pos;

        if (chunk <= remaining) {
            memcpy(rb->buffer + rb->write_pos, data, chunk);
            rb->write_pos += chunk;
        } else {
            memcpy(rb->buffer + rb->write_pos, data, remaining);
            memcpy(rb->buffer, data + remaining, chunk - remaining);
            rb->write_pos = chunk - remaining;
        }

        data += chunk;
        length -= chunk;
        written += chunk;
        space = ring_buffer_space_available(rb);
    }

    // printf("read ring buffer write end......\n");

    return written;
}

// 从缓冲区读取数据
int ring_buffer_read(RingBuffer *rb, char *data, int length, int *readLen) {
  *readLen = 0;
  int needLen;
  while (length != *readLen) {
    needLen = length - *readLen;
    while (ring_buffer_space_used(rb) == 0 && rb->running) {
        ;
    }
    if (!rb->running && ring_buffer_space_used(rb) == 0) {
        return 0;
    }

    int used = ring_buffer_space_used(rb);
    int read = (used < needLen) ? used : needLen;

    int totalRead = 0;

    // printf("read ring buffer read start......\n");

    while (read > 0) {
        int chunk = (read < used) ? read : used;
        int remaining = BUFFER_SIZE - rb->read_pos;

        if (chunk <= remaining) {
            memcpy(data, rb->buffer + rb->read_pos, chunk);
            rb->read_pos += chunk;
        } else {
            memcpy(data, rb->buffer + rb->read_pos, remaining);
            memcpy(data + remaining, rb->buffer, chunk - remaining);
            rb->read_pos = chunk - remaining;
        }

        data += chunk;
        read -= chunk;
        totalRead += chunk;
    }

    // printf("read ring buffer read start......\n");

    *readLen += totalRead;
  }
  return 1;
}

// 设置ring_buffer的运行状态为停止
void ring_buffer_stop(RingBuffer *rb) {
  rb->running = 0;
}

// 判断释放ring_buffer释放的时机
void ring_buffer_already_got() {
  while (tempRB != NULL)
  {
    ;
  }

  // 说明tempRB == NULL
  return;
  
}


