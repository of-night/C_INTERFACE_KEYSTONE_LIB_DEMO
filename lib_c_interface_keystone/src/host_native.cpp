#include <edge_call.h>
#include <keystone.h>
#include "ipfs_keystone.h"
#include <iostream>
#include <chrono>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h>


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
  params.setUntrustedSize(2 * 1024 * 1024);

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

  std::cout << "enclave done!" << std::endl;
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


// ==================================================================================
//									MultiTheaded Keystone Aes encrypt
// ==================================================================================

// 初始化半部分缓冲区
void init_half_part_buffer(HalfPartBuffer *pb, int buffersize) {

    pb->read_pos = 0;
    pb->write_pos = 0;
    pb->buffer = (char*)malloc(buffersize);
    if (pb->buffer == NULL)
    {
        printf("malloc hpb buffer error!\n");
        return;
    }
    pb->MaxSpace = buffersize;
    
    pb->running = 1;
}

// 初始化多线程缓冲区
void init_multi_threaded_ring_buffer(MultiThreadedBuffer *mtb, int fileSize, int sizeppb) {
  // 16字节对齐，满足加密数据存储空间的需求
  // CHUNK_SIZE = 2 ^ 18 = 256 * 1024
  // 0x3 = 0b0011, 0xf = 0b1111
  // fileSize = (fileSize + 0xf) &~0xf;
  // int AfileSize = (fileSize &~0x3ffff) >> 1;
  // 初始化前半部分缓冲区
  init_half_part_buffer(&mtb->ppb, sizeppb);
  // 初始化后半部分缓冲区
  init_half_part_buffer(&mtb->hpb, fileSize - sizeppb);

}

// 释放半部分缓冲区
void destory_half_part_buffer(HalfPartBuffer *pb) {
    if (pb->buffer != NULL) {
      pb->buffer = NULL;
      free(pb->buffer); 
    }
}

// 释放多线程缓冲区
void destory_multi_threaded_ring_buffer(MultiThreadedBuffer *mtb) {
    if (mtb != NULL)
    {
        destory_half_part_buffer(&mtb->ppb);
        destory_half_part_buffer(&mtb->hpb);
        free(mtb);
    }
}

MultiFile* MULTIADDFILENAMEPPB = NULL;
MultiFile* MULTIADDFILENAMEHPB = NULL;
HalfPartBuffer* temPPB = NULL;
HalfPartBuffer* temHPB = NULL;

#define OCALL_PRINT_STRING          1
// #define OCALL_PB_GET_FILENAMESIZE   5
#define OCALL_PPB_GET_FILENAMESIZE  5
#define OCALL_HPB_GET_FILENAMESIZE  6
// #define OCALL_PB_BUFFER_WRITE       7
#define OCALL_PPB_BUFFER_WRITE      7
#define OCALL_PPB_BUFFER_READ       8
#define OCALL_HPB_BUFFER_WRITE      9
#define OCALL_HPB_BUFFER_READ       10

void get_ppb_filenamesize_wrapper(void* buffer);
void ppb_buffer_write_wrapper(void* buffer);
void get_hpb_filenamesize_wrapper(void* buffer);
void hpb_buffer_write_wrapper(void* buffer);

int pb_buffer_write(HalfPartBuffer *pb, const char *data, size_t length);


void delete_MULTIADDFILENAM(MultiFile* f) {
  if (f == NULL)
  {
    printf("Delete MultiFile is NULL, delete error\n");
    return;
  }
  
  free(f);
  f = NULL;
}

void init_MULTIADDFILENAM(MultiFile* f, char* fileName, int offset, int maxspace) {
  size_t len = strlen(fileName) + 1;
  if (len > 20)
  {
    printf("fileName is too long \n");
    delete_MULTIADDFILENAM(f);
    return;
  }
  
  memcpy(f->fileName, fileName, strlen(fileName));
  // f->fileName = fileName;
  f->offset = offset;
  f->maxspace = maxspace;
}

void multi_ipfs_keystone_ppb_buffer(int isAES, void* fileName, void* pb, int offset, int maxspace) {
  if (fileName == NULL) { 
    printf("multi_ipfs_keystone_ppb_buffer fileName is NULL\nERROR CLOSE......\n");
    return;
  }

  printf("ppb filename: %s\n", (char*)fileName);

  MULTIADDFILENAMEPPB = (MultiFile*)malloc(sizeof(MultiFile));
  if (MULTIADDFILENAMEPPB == NULL) {
    printf("multi_ipfs_keystone_ppb_filename malloc MULTIADDFILENAMEPPB memory error\nERROR CLOSE...\n");
    return;
  }

  init_MULTIADDFILENAM(MULTIADDFILENAMEPPB, (char*)fileName, offset, maxspace);

  printf("MULTIADDFILENAMEPPB filename: %s\n", MULTIADDFILENAMEPPB->fileName);

  if (MULTIADDFILENAMEPPB == NULL) {
    printf("multi_ipfs_keystone_ppb_filename init error\nERROR CLOSE...\n");
    return;
  }

  if (pb == NULL)
  {
    printf("multi_ipfs_keystone_ppb_buffer pb is NULL\nERROR CLOSE...\n"); 
    delete_MULTIADDFILENAM(MULTIADDFILENAMEPPB);
  }

  temPPB = (HalfPartBuffer*)pb;

  // 获取当前时间点
  auto start = std::chrono::steady_clock::now();

  Keystone::Enclave enclave;
  Keystone::Params params;

  params.setFreeMemSize(256 * 1024 * 1024);
  params.setUntrustedSize(2 * 1024 * 1024);

  switch (isAES)
  {
  case AES:
      enclave.init("multiaes_1", "eyrie-rt", "loader.bin", params);
      break;
  case SM4:
      enclave.init("multism4_1", "eyrie-rt", "loader.bin", params);
      break;
  case demo:
      enclave.init("hello-native", "eyrie-rt", "loader.bin", params);
      break;
  default:
      std::cout << "multiTEE do nothing" << std::endl;
      return;
  }

  enclave.registerOcallDispatch(incoming_call_dispatch);

  /* We must specifically register functions we want to export to the
     enclave. */
  register_call(OCALL_PRINT_STRING, print_string_wrapper);
  register_call(OCALL_PPB_GET_FILENAMESIZE, get_ppb_filenamesize_wrapper);
  register_call(OCALL_PPB_BUFFER_WRITE, ppb_buffer_write_wrapper);

  edge_call_init_internals(
      (uintptr_t)enclave.getSharedBuffer(), enclave.getSharedBufferSize());

  auto end = std::chrono::steady_clock::now();
  std::chrono::duration<double, std::micro> elapsed = end - start;
  std::cout << "Elapsed time: " << elapsed.count() << " microseconds" << std::endl;

  enclave.run();

  temPPB->running = 0;

  delete_MULTIADDFILENAM(MULTIADDFILENAMEPPB);

  std::cout << "PPB enclave done" << std::endl;
}

void multi_ipfs_keystone_ppb_buffer_wrapper(int isAES, void* fileName, void* mtb, int offset, int maxspace) {
  multi_ipfs_keystone_ppb_buffer(isAES, fileName, (void*)&(((MultiThreadedBuffer*)mtb)->ppb), offset, maxspace);
}

void multi_ipfs_keystone_hpb_buffer(int isAES, void* fileName, void* pb, int offset, int maxspace) {
  if (fileName == NULL) { 
    printf("multi_ipfs_keystone_hpb_buffer fileName is NULL\nERROR CLOSE......\n");
    return;
  }

  printf("hpb filename: %s\n", (char*)fileName);

  MULTIADDFILENAMEHPB = (MultiFile*)malloc(sizeof(MultiFile));
  if (MULTIADDFILENAMEHPB == NULL) {
    printf("multi_ipfs_keystone_hpb_filename malloc MULTIADDFILENAMEHPB memory error\nERROR CLOSE...\n");
    return;
  }

  init_MULTIADDFILENAM(MULTIADDFILENAMEHPB, (char*)fileName, offset, maxspace);

  printf("MULTIADDFILENAMEHPB filename: %s\n", MULTIADDFILENAMEHPB->fileName);
  
  if (MULTIADDFILENAMEHPB == NULL)
  {
    printf("multi_ipfs_keystone_hpb_filename init error\nERROR CLOSE...\n");
    return;
  }
  
  if (pb == NULL)
  {
    printf("multi_ipfs_keystone_hpb_buffer pb is NULL\nERROR CLOSE...\n");
    delete_MULTIADDFILENAM(MULTIADDFILENAMEHPB);
    return;
  }

  temHPB = (HalfPartBuffer*)pb;

  // 获取当前时间点
  auto start = std::chrono::steady_clock::now();

  Keystone::Enclave enclave;
  Keystone::Params params;

  params.setFreeMemSize(256 * 1024 * 1024);
  params.setUntrustedSize(2 * 1024 * 1024);

  switch (isAES)
  {
  case AES:
      enclave.init("multiaes_2", "eyrie-rt", "loader.bin", params);
      break;
  case SM4:
      enclave.init("multism4_2", "eyrie-rt", "loader.bin", params);
      break;
  case demo:
      enclave.init("hello-native", "eyrie-rt", "loader.bin", params);
      break;
  default:
      std::cout << "multiTEE do nothing" << std::endl;
      return;
  }

  enclave.registerOcallDispatch(incoming_call_dispatch);

  /* We must specifically register functions we want to export to the
     enclave. */
  register_call(OCALL_PRINT_STRING, print_string_wrapper);
  register_call(OCALL_HPB_GET_FILENAMESIZE, get_hpb_filenamesize_wrapper);
  register_call(OCALL_HPB_BUFFER_WRITE, hpb_buffer_write_wrapper);

  edge_call_init_internals(
      (uintptr_t)enclave.getSharedBuffer(), enclave.getSharedBufferSize());

  auto end = std::chrono::steady_clock::now();
  std::chrono::duration<double, std::micro> elapsed = end - start;
  std::cout << "Elapsed time: " << elapsed.count() << " microseconds" << std::endl;

  enclave.run();

  temHPB->running = 0;

  delete_MULTIADDFILENAM(MULTIADDFILENAMEHPB);

  std::cout << "HPB enclave done" << std::endl;
}

void multi_ipfs_keystone_hpb_buffer_wrapper(int isAES, void* fileName, void* mtb, int offset, int maxspace) {
  multi_ipfs_keystone_hpb_buffer(isAES, fileName, (void*)&(((MultiThreadedBuffer*)mtb)->hpb), offset, maxspace);
}

int alignedFileSize(int fileSize) {
  return ((fileSize + 0xf) &~0xf);
}

int aFileSize(int fileSize) {
  // return ((fileSize & ~0x3ffff) >> 1);
  return (fileSize >> 1) & ~0x3ffff;
  // return ((fileSize & ~0x3ffff) >> 1) & ~0x3ffff;
}

void get_ppb_filenamesize_wrapper(void* buffer) {

  struct edge_call* edge_call = (struct edge_call*)buffer;
  uintptr_t call_args;
  size_t arg_len;
  if (edge_call_args_ptr(edge_call, &call_args, &arg_len) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  if (MULTIADDFILENAMEPPB == NULL) {
    std::cout << "MULTIADDFILENAMEPPB == NULL in get_ppb_filenamesize_wrapper. MULTIADDFILENAMEPPB: " << MULTIADDFILENAMEPPB << std::endl;
    return;
  }

  printf("MULTIADDFILENAMEPPB filename: %s file offset: %d file maxspace: %d\n", MULTIADDFILENAMEPPB->fileName, MULTIADDFILENAMEPPB->offset, MULTIADDFILENAMEPPB->maxspace);

  if (edge_call_setup_wrapped_ret(edge_call, (void*)MULTIADDFILENAMEPPB, sizeof(MultiFile))) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  } else {
    edge_call->return_data.call_status = CALL_STATUS_OK;
  }
  
  return;
} 

void get_hpb_filenamesize_wrapper(void* buffer) {

  struct edge_call* edge_call = (struct edge_call*)buffer;
  uintptr_t call_args;
  size_t arg_len;
  if (edge_call_args_ptr(edge_call, &call_args, &arg_len) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  if (MULTIADDFILENAMEHPB == NULL) {
    std::cout << "MULTIADDFILENAMEHPB == NULL in get_hpb_filenamesize_wrapper. MULTIADDFILENAMEHPB: " << MULTIADDFILENAMEHPB << std::endl;
    return;
  }

  printf("MULTIADDFILENAMEHPB filename: %s file offset: %d file maxspace: %d\n", MULTIADDFILENAMEHPB->fileName, MULTIADDFILENAMEHPB->offset, MULTIADDFILENAMEHPB->maxspace);

  if (edge_call_setup_wrapped_ret(edge_call, (void*)MULTIADDFILENAMEHPB, sizeof(MultiFile))) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  } else {
    edge_call->return_data.call_status = CALL_STATUS_OK;
  }
  
  return;
}

int pb_buffer_write(HalfPartBuffer *pb, const char *data, size_t length) {
  if (pb->MaxSpace - pb->write_pos < length)
  {
    printf("write buffer error, pb space is not enough\n");
    return -1;
  }
  
  memcpy(&pb->buffer[pb->write_pos], data, length);
  pb->write_pos += length;

  return length;
  
}

void ppb_buffer_write_wrapper(void* buffer) {
  struct edge_call* edge_call = (struct edge_call*)buffer;
  uintptr_t call_args;
  size_t arg_len;
  if (edge_call_args_ptr(edge_call, &call_args, &arg_len) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  if (temPPB == NULL)
  {
    std::cout << "temPPB == NULL in ppb_buffer_write_wrapper. temPPB: " << temPPB << std::endl;
    return;
  }

  if (arg_len >= 0) {
    printf("phpb start write buffer start\n");
    if (pb_buffer_write(temPPB, (char *)call_args, arg_len) >= 0) {
      edge_call->return_data.call_status = CALL_STATUS_OK;
      return;
    }
    printf("ppb start write buffer end\n");
  }

  edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;

  return;
}

void hpb_buffer_write_wrapper(void* buffer) {
  struct edge_call* edge_call = (struct edge_call*)buffer;
  uintptr_t call_args;
  size_t arg_len;
  if (edge_call_args_ptr(edge_call, &call_args, &arg_len) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  if (temHPB == NULL)
  {
    std::cout << "temHPB == NULL in hpb_buffer_write_wrapper. temHPB: " << temHPB << std::endl;
    return;
  }

  if (arg_len >= 0) {
    printf("hpb start write buffer start\n");
    if (pb_buffer_write(temHPB, (char *)call_args, arg_len) >= 0) {
      edge_call->return_data.call_status = CALL_STATUS_OK;
      return;
    }
    printf("hpb start write buffer end\n");
  }

  edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;

  return;
}

// ipfs从buffer中读取数据
int which_pb_buffer_read(MultiThreadedBuffer *mtb, char *data, int length, int *readLen) {
  // 前半部分缓冲区数据获取完
  if (mtb->ppb.read_pos == mtb->ppb.MaxSpace) {
    // 当hpb buffer中数据足够length 或者 hpb buffer不在再运行、代表数据已经全部放入buffer中了
    // buffer[read_pos] -- buffer[read_pos + length] 的数据
    while (mtb->hpb.read_pos + length > mtb->hpb.write_pos && mtb->hpb.running)
    {
      ;
    }

    if (!mtb->hpb.running && (mtb->hpb.read_pos == mtb->hpb.MaxSpace)) {
      return 0;
    }

    int used = mtb->hpb.write_pos - mtb->hpb.read_pos;
    int readsize = used < length ? used : length;
    
    memcpy(data, &mtb->hpb.buffer[mtb->hpb.read_pos], readsize);
    mtb->hpb.read_pos += readsize;
    *readLen = readsize;

    return 1;
  }

  // 获取前半部分数据
  while (mtb->ppb.read_pos + length > mtb->ppb.write_pos && mtb->ppb.running) {
    ;
  }
  
  // if (!mtb->ppb.running && (mtb->ppb.read_pos == mtb->ppb.MaxSpace)) {
  //     return 0;
  // }

  int used = mtb->ppb.write_pos - mtb->ppb.read_pos;
  
  if (used < length) {
    printf("ppb buffer data ERROR, remaining data size is not chunk size\n");
    printf("write_pos: %d \t read_pos: %d \t used: %d \n",mtb->ppb.write_pos ,mtb->ppb.read_pos, used);
    return 0;
  }

  memcpy(data, &mtb->ppb.buffer[mtb->ppb.read_pos], length);
  mtb->ppb.read_pos += length;
  *readLen = length;

  return 1;

}



// ==================================================================================
//				Multi-process Keystone Encrypt
// ==================================================================================


int MultiProcessRead(void* shmaddr, int shmsize, void* data, int len, int* readLen) {
  MultiProcessSHMBuffer* tempmpshmb = (MultiProcessSHMBuffer*)shmaddr;

  // int src_offset = sizeof(MultiProcessSHMBuffer) + tempmpshmb->offset;
  int src_offset = sizeof(MultiProcessSHMBuffer);
  
  // 说明前半部分缓冲区已经正常读到预定的末尾位置，开始获取后半部分的数据
  if (tempmpshmb->qpb.read_pos == tempmpshmb->qpb.MaxSpace) {
    while (tempmpshmb->hpb.read_pos + len > tempmpshmb->hpb.write_pos && tempmpshmb->hpb.running)
    {
      ;
    }

    int hpb_src_offset = src_offset + tempmpshmb->qpb.MaxSpace;

    if (!tempmpshmb->hpb.running && (tempmpshmb->hpb.read_pos == tempmpshmb->hpb.write_pos)) {
      printf("write - max = %d\n", tempmpshmb->hpb.write_pos - tempmpshmb->hpb.MaxSpace);
      printf("read - max = %d\n", tempmpshmb->hpb.read_pos - tempmpshmb->hpb.MaxSpace);
      return 0;
    }

    int used = tempmpshmb->hpb.write_pos - tempmpshmb->hpb.read_pos;
    int read_size = len < used ? len : used;

    memcpy(data, (void*)((char*)shmaddr + hpb_src_offset + tempmpshmb->hpb.read_pos), read_size);
    tempmpshmb->hpb.read_pos += read_size;
    *readLen = read_size;
    return 1;
    
  }

  while (tempmpshmb->qpb.read_pos + len > tempmpshmb->qpb.write_pos && tempmpshmb->qpb.running)
  {
    ;
  }

  int used = tempmpshmb->qpb.write_pos - tempmpshmb->qpb.read_pos;
  if (used < len) {
    printf("qpb buffer data ERROR, remaining data size is not chunk size\n");
    return 0;
  }
  
  memcpy(data, (void*)((char*)shmaddr + src_offset + tempmpshmb->qpb.read_pos), len);
  tempmpshmb->qpb.read_pos += len;
  *readLen = len;
  return 1;
  
}

// 创建共享内存
void *creat_shareMemory(int shmsize) {
  int id = shmget(shmKey, shmsize, IPC_CREAT | 0666);
  if (id == -1) {
    perror("Failed to get shared memory");
    exit(-1);
  }

  void* shmaddr = shmat(id, NULL, 0);
  if (shmaddr == (void *)-1) {
    perror("Failed to attach shared memory");
    exit(-1);
  }

  return shmaddr;
}

// 为当前进程连接共享内存
void *attach_shareMemory(int shmsize) {
  int id = shmget(shmKey, shmsize, 0666);
  if (id == -1) {
    perror("Failed to get shared memory");
    exit(-1);
  }

  void* shmaddr = shmat(id, NULL, 0);
  if (shmaddr == (void *)-1) {
    perror("Failed to attach shared memory");
    exit(-1);
  }

  return shmaddr;
}

// 断开连接共享内存
void detach_shareMemory(void* shmaddr) {
  shmdt(shmaddr);
}

// 删除共享内存段
void removeShm(int shmsize) {

  int id = shmget(shmKey, shmsize, 0666);
  if (id == -1) {
    perror("Failed to get shared memory");
    exit(-1);
  }

  if (shmctl(id, IPC_RMID, NULL) == -1) {
    perror("shmctl");
    exit(-1);
  }
}

void waitKeystoneReady(void *shmaddr) {
  MultiProcessSHMBuffer* tempmpshmb = (MultiProcessSHMBuffer*)shmaddr;

  while (tempmpshmb->offset != sizeof(MultiProcessSHMBuffer))
  {
    ;
  }
  
}




// ==================================================================================
//				Multi-process Cross-read Keystone Encrypt
// ==================================================================================

long long long_alignedFileSize(long long fileSize) {
  return ((fileSize + 0xf) &~0xf);
}

long long long_alignedFileSize_blocksnums(long long fileSize) {
  return ((fileSize + 0x3ffff)>> 18);
}

// 创建共享内存
void *long_create_shareMemory(long long shmsize) {
  int id = shmget(shmKey, shmsize, IPC_CREAT | 0666);
  if (id == -1) {
    perror("Failed to get shared memory");
    exit(-1);
  }

  void* shmaddr = shmat(id, NULL, 0);
  if (shmaddr == (void *)-1) {
    perror("Failed to attach shared memory");
    exit(-1);
  }

  return shmaddr;
}

// 删除共享内存段
void long_removeShm(long long shmsize) {

  int id = shmget(shmKey, shmsize, 0666);
  if (id == -1) {
    perror("Failed to get shared memory");
    exit(-1);
  }

  if (shmctl(id, IPC_RMID, NULL) == -1) {
    perror("shmctl");
    exit(-1);
  }
}

// 启动keystone之前先初始化内存空间
void crossInitSHM(void *shmaddr, long long blocksNums) {
  MultiProcessCrossSHMBuffer *tMCSM = (MultiProcessCrossSHMBuffer*)shmaddr;

  tMCSM->offset = blocksNums * (sizeof(unsigned int));
  tMCSM->ready1 = 0;
  tMCSM->ready2 = 0;
  tMCSM->read_position = 0;

  unsigned int* tflag = (unsigned int*)((char*)shmaddr + sizeof(MultiProcessCrossSHMBuffer));

  for (int i = 0; i < blocksNums; ++i) {
    tflag[i] = 0;
  }
  
}

// 等待keystone already
void crosswaitKeystoneReady(void *shmaddr) {
  MultiProcessCrossSHMBuffer *tMCSM = (MultiProcessCrossSHMBuffer*)shmaddr;

  while (tMCSM->ready1 != 1 || tMCSM->ready2 != 1)
  {
    ;
  }
  
}

int MultiProcessCrossRead(void* shmaddr, int shmsize, void* data, int len, int* readLen) {
  MultiProcessCrossSHMBuffer* tempmpshmb = (MultiProcessCrossSHMBuffer*)shmaddr;

  unsigned int* src_offset_flag = (unsigned int*)((char*)shmaddr + sizeof(MultiProcessCrossSHMBuffer));
  char* src_offset_data = (char*)shmaddr + sizeof(MultiProcessCrossSHMBuffer) + tempmpshmb->offset;

  while (src_offset_flag[tempmpshmb->read_position] == 0 && (tempmpshmb->offset > (tempmpshmb->read_position * 4)))
  {
    ;
  }

  if (tempmpshmb->offset <= (tempmpshmb->read_position * 4)) {
    return 0;
  }

  if (src_offset_flag[tempmpshmb->read_position] == 0) {
    printf("Keystone write data error\n");
    return 0;
  }

  *readLen = len > src_offset_flag[tempmpshmb->read_position] ? src_offset_flag[tempmpshmb->read_position] : len;

  memcpy(data, src_offset_data + ((tempmpshmb->read_position) << 18), *readLen);
  tempmpshmb->read_position += 1;

  // printf("read_position:%d\n offset:%d\n", tempmpshmb->read_position, tempmpshmb->offset);

  return 1;
  
}




// ==================================================================================
//				Multi-process Cross-read Flexible Keystone Encrypt
// ==================================================================================

// MAXNUM 10
void fixFlexibleNum(void* flexible) {
    *(int*)flexible = MAXKEYSTONENUMBER > *(int*)flexible ? *(int*)flexible : MAXKEYSTONENUMBER;
    return;
}

// 启动keystone之前先初始化内存空间
void flexiblecrossInitSHM(void *shmaddr, long long blocksNums) {
  MultiProcessCrossFlexibleSHMBuffer *tMCFSM = (MultiProcessCrossFlexibleSHMBuffer*)shmaddr;

  tMCFSM->offset = blocksNums * (sizeof(unsigned int));
  for (int i = 0; i < MAXKEYSTONENUMBER; ++i) {
    tMCFSM->ready[i] = 0;
  }
  tMCFSM->read_position = 0;

  unsigned int* tflag = (unsigned int*)((char*)shmaddr + sizeof(MultiProcessCrossFlexibleSHMBuffer));

  for (int i = 0; i < blocksNums; ++i) {
    tflag[i] = 0;
  }
  
}

// 等待keystone already
void flexiblecrosswaitKeystoneReady(void *shmaddr, int flexible) {
  MultiProcessCrossFlexibleSHMBuffer *tMCFSM = (MultiProcessCrossFlexibleSHMBuffer*)shmaddr;

  int flag = 0;

  while (flag  == flexible)
  {
    if (tMCFSM->ready[flag] == 1) {
      flag += 1;
    }
  }
  
}

int MultiProcessCrossReadFlexible(void* shmaddr, int shmsize, void* data, int len, int* readLen) {
  MultiProcessCrossFlexibleSHMBuffer* tMPCFSB = (MultiProcessCrossFlexibleSHMBuffer*)shmaddr;

  unsigned int* src_offset_flag = (unsigned int*)((char*)shmaddr + sizeof(MultiProcessCrossFlexibleSHMBuffer));
  char* src_offset_data = (char*)shmaddr + sizeof(MultiProcessCrossFlexibleSHMBuffer) + tMPCFSB->offset;

  while (src_offset_flag[tMPCFSB->read_position] == 0 && (tMPCFSB->offset > (tMPCFSB->read_position * 4)))
  {
    ;
  }

  if (tMPCFSB->offset <= (tMPCFSB->read_position * 4)) {
    return 0;
  }

  if (src_offset_flag[tMPCFSB->read_position] == 0) {
    printf("Keystone write data error\n");
    return 0;
  }

  *readLen = len > src_offset_flag[tMPCFSB->read_position] ? src_offset_flag[tMPCFSB->read_position] : len;

  memcpy(data, src_offset_data + ((tMPCFSB->read_position) << 18), *readLen);
  tMPCFSB->read_position += 1;

  // printf("read_position:%d\n offset:%d\n", tMPCFSB->read_position, tMPCFSB->offset);

  return 1;
  
}


// ==================================================================================
//				Multi-process Keystone Decrypt
// ==================================================================================

static unsigned long long DISPATHsize = 0ULL;

static unsigned long long DISPATH_engine_seq = 0ULL;

// 设置总大小
void dispathSetLength(unsigned long long size) {
  DISPATHsize = size;
}

unsigned long long getDispathEngineSeq() {
  return ++DISPATH_engine_seq;
}

// 获取总大小
void dispathGetLength(unsigned long long *size) {
  *size = DISPATHsize;
}

// 计算每个enclave最少dispath的blocks数量，和剩余的数量
void dispath_blocks(unsigned long long fileSize, void* eblock, void* seblock, int flexible) {
  long long blockNumbers =  ((fileSize + 0x3ffff)>> 18);
  *(long long*)eblock = blockNumbers / flexible;
  *(long long*)seblock = blockNumbers % flexible;
}

// 创建共享内存
void *dispath_long_create_shareMemory(long long shmsize, int en_id) {
  int id = shmget(dispath_shmKey + en_id, shmsize, IPC_CREAT | 0666);
  if (id == -1) {
    perror("Failed to get shared memory");
    exit(-1);
  }

  void* shmaddr = shmat(id, NULL, 0);
  if (shmaddr == (void *)-1) {
    perror("Failed to attach shared memory");
    exit(-1);
  }

  return shmaddr;
}

// 断开连接共享内存
void dispath_detach_shareMemory(void* shmaddr) {
  shmdt(shmaddr);
}

// 删除共享内存段
void dispath_long_removeShm(long long shmsize, int en_id) {

  int id = shmget(dispath_shmKey+en_id, shmsize, 0666);
  if (id == -1) {
    perror("Failed to get shared memory");
    exit(-1);
  }

  if (shmctl(id, IPC_RMID, NULL) == -1) {
    perror("shmctl");
    exit(-1);
  }
}

// 启动keystone之前先初始化内存空间
void dispath_InitSHM(void *shmaddr, long long blocksNums) {
  MultiProcessTEEDispatchSHMBuffer *dispathSHM = (MultiProcessTEEDispatchSHMBuffer*)shmaddr;

  dispathSHM->offset = blocksNums * (sizeof(unsigned int));
  dispathSHM->ready = 0;
  dispathSHM->read_position = 0;

  unsigned int* tflag = (unsigned int*)((char*)shmaddr + sizeof(MultiProcessTEEDispatchSHMBuffer));

  for (int i = 0; i < blocksNums; ++i) {
    tflag[i] = 0;
  }
  
}

// 等待keystone already
int dispathwaitKeystoneReady(void *shmaddr) {
  MultiProcessTEEDispatchSHMBuffer *dispathSHM = (MultiProcessTEEDispatchSHMBuffer*)shmaddr;

  return dispathSHM->ready;
}  

// 计算bnumber
long long dispathBNumber(long long* blockcount, int flexible) {
  return (*blockcount)++ % flexible;
}

// 调度器将数据读取到调度器与enclave之间的共享内存中
int dispath_data_block(void *shmaddr, long long shmsize, char* p, int pLen, int* readLen) {
  MultiProcessTEEDispatchSHMBuffer *dispathSHM = (MultiProcessTEEDispatchSHMBuffer*)shmaddr;
  
  unsigned int* tflag = (unsigned int*)((char*)shmaddr + sizeof(MultiProcessTEEDispatchSHMBuffer));

  long long i = dispathSHM->read_position++;

  // std::cout << "ipfs host_native testing 1" << std::endl;
  // std::cout << "ipfs host_native testing i = " << i << std::endl;

  if (i<<2 > dispathSHM->offset) return 0;

  // std::cout << "ipfs host_native testing i = " << i << std::endl;
  long long dataOffset = sizeof(MultiProcessTEEDispatchSHMBuffer) + dispathSHM->offset + (i<<18);

  // std::cout << "ipfs host_native testing 1" << std::endl;
  // std::cout << "ipfs host_native testing sizeof(MultiProcessTEEDispatchSHMBuffer)" << sizeof(MultiProcessTEEDispatchSHMBuffer) << std::endl;
  // std::cout << "ipfs host_native testing dispathSHM->offset" << dispathSHM->offset << std::endl;
  // std::cout << "ipfs host_native testing dataOffset" << dataOffset << std::endl;
  // std::cout << "ipfs host_native testing pLen" << pLen << std::endl;
  // std::cout << "ipfs host_native testing shmsize" << shmsize << std::endl;
  if (dataOffset + pLen > shmsize) return 0;
  // std::cout << "ipfs host_native testing shmsize" << shmsize << std::endl;

  char* dataSrc =(char*)shmaddr + dataOffset;

  memcpy(dataSrc, p, pLen);
  tflag[i] = *readLen = pLen;

  // std::cout << "ipfs host_native testing " << tflag[i] << ", " << *readLen << ", " << pLen << std::endl;
  return 1;
}

// 调度器将数据读取到调度器与enclave之间的共享内存中
int dispath_data_block_4096(void *shmaddr, long long shmsize, char* p, int pLen, int* readLen) {
  MultiProcessTEEDispatchSHMBuffer *dispathSHM = (MultiProcessTEEDispatchSHMBuffer*)shmaddr;
  
  unsigned int* tflag = (unsigned int*)((char*)shmaddr + sizeof(MultiProcessTEEDispatchSHMBuffer));

  long long i = dispathSHM->read_position;
  long long yxbytes = tflag[i];

  // std::cout << "ipfs host_native testing 1" << std::endl;
  // std::cout << "ipfs host_native testing i = " << i << std::endl;

  if (i<<2 > dispathSHM->offset)  {
    std::cout << "ipfs host_native error i<<2 > dispathSHM->offset= " << dispathSHM->offset << std::endl;
    return 0;
  }

  // std::cout << "ipfs host_native testing i = " << i << std::endl;
  long long dataOffset = sizeof(MultiProcessTEEDispatchSHMBuffer) + dispathSHM->offset + (i<<18) + yxbytes;

  // std::cout << "ipfs host_native testing 1" << std::endl;
  // std::cout << "ipfs host_native testing sizeof(MultiProcessTEEDispatchSHMBuffer)" << sizeof(MultiProcessTEEDispatchSHMBuffer) << std::endl;
  // std::cout << "ipfs host_native testing dispathSHM->offset" << dispathSHM->offset << std::endl;
  // std::cout << "ipfs host_native testing dataOffset" << dataOffset << std::endl;
  // std::cout << "ipfs host_native testing pLen" << pLen << std::endl;
  // std::cout << "ipfs host_native testing shmsize" << shmsize << std::endl;
  if (dataOffset + pLen > shmsize) { 
    std::cout << "ipfs host_native error dataOffset + pLen = " << dataOffset + pLen << " > shmsize " << shmsize << std::endl;
    return 0;
  }
  // std::cout << "ipfs host_native testing shmsize" << shmsize << std::endl;

  char* dataSrc =(char*)shmaddr + dataOffset;

  if (tflag[i] + pLen > 262144) {
    std::cout << "ipfs host_native error tflag[i] + pLen " << tflag[i] + pLen << std::endl;
    return 0;
  }

  memcpy(dataSrc, p, pLen);
  *readLen = pLen;
  tflag[i] += pLen;

  if (tflag[i] == 256*1024) dispathSHM->read_position++;

  if (dataOffset + pLen == shmsize) {
    dispathSHM->read_position++;
  }

  // std::cout << "ipfs host_native testing " << tflag[i] << ", " << *readLen << ", " << pLen << "dispathSHM->read_position=" << dispathSHM->read_position << std::endl;
  return 1;
}




// ==================================================================================
//				Multi-process Keystone Decrypt secure dispatch
// ==================================================================================

// create shm
void* secure_dispatch_ulnoglong_create_shareMemory(unsigned long long shmsize) {
  int id = shmget(SECURE_DISPATCH_SHMKEY, shmsize, IPC_CREAT | 0666);
  if (id == -1) {
    perror("Failed to get shared memory");
    exit(-1);
  }

  void* shmaddr = shmat(id, NULL, 0);
  if (shmaddr == (void *)-1) {
    perror("Failed to attach shared memory");
    exit(-1);
  }

  return shmaddr;
}

// detach shm
void secure_dispatch_detach_shareMemory(void* shmaddr) {
  shmdt(shmaddr);
}

// remove shm
void secure_dispatch_ulnoglong_remove_shareMemory(unsigned long long shmsize) {
  int id = shmget(SECURE_DISPATCH_SHMKEY, shmsize, 0666);
  if (id == -1) {
    perror("Failed to get shared memory");
    exit(-1);
  }

  if (shmctl(id, IPC_RMID, NULL) == -1) {
    perror("shmctl");
    exit(-1);
  }
}

// init shm
void secure_dispacth_initSHM(void* shmaddr, unsigned long long blockNum, int flexible) {
  int *enclave_ready = (int*)shmaddr;
  for (int i = 0; i < flexible; ++i) {
    enclave_ready[i] = 0;
  }

  int transfer_to_main_offset = (sizeof(int) * flexible);
  MultiProcessTEESecureDispatchSHMBuffer *transfer_to_main = (MultiProcessTEESecureDispatchSHMBuffer*)((char*)shmaddr + transfer_to_main_offset);
  transfer_to_main->read_position = 0;
  transfer_to_main->offset = transfer_to_main_offset + sizeof(MultiProcessTEESecureDispatchSHMBuffer) + (blockNum * sizeof(int));

  int *blockNum_flag = (int*)((char*)shmaddr + transfer_to_main_offset + sizeof(MultiProcessTEESecureDispatchSHMBuffer));
  for (int i = 0; i < blockNum; ++i) {
    blockNum_flag[i] = 0;
  }

}

// get shmsize
unsigned long long MultiProcessTEESecureDispatchGetSHMSize(unsigned long long fileSize, void* blockNum, int flexible) {
  *(unsigned long long*)blockNum = ((fileSize + 0x3ffff)>> 18);
  return (sizeof(int) * flexible) + sizeof(MultiProcessTEESecureDispatchSHMBuffer) + (((fileSize + 0x3ffff)>> 18) * sizeof(int)) + fileSize;
}

// 等待keystone already
void secure_dispatch_waitKeystoneReady(void *shmaddr, int flexible){
  int *enclave_ready = (int*)shmaddr;

  for (int i = (flexible - 1); i >= 0; i--) {
    while(1) {
      if (enclave_ready[i] == 1) {
        break;
      }
    }
  }
}

// 等待keystone done
void secure_dispatch_waitKeystoneDone(void *shmaddr, int flexible){
  int *enclave_ready = (int*)shmaddr;

  for (int i = (flexible -1); i >= 0; i--) {
    while(1) {
      if (enclave_ready[i] == 2) {
        break;
      }
    }
  }
}

int secure_dispatch_write(void *shmaddr, long long shmsize, char* p, int pLen, int* readLen, int flexible) {
  int transfer_to_main_offset = (sizeof(int) * flexible);
  MultiProcessTEESecureDispatchSHMBuffer *transfer_to_main = (MultiProcessTEESecureDispatchSHMBuffer*)((char*)shmaddr + transfer_to_main_offset);
  
  int i = transfer_to_main->read_position;

  long long blockNum_flag_offset = transfer_to_main_offset + sizeof(MultiProcessTEESecureDispatchSHMBuffer);
  int *blockNum_flag = (int*)((char*)shmaddr + blockNum_flag_offset);

  long long block_data_offset = transfer_to_main->offset + (i << 18) + blockNum_flag[i];
  char *block_data = (char*)shmaddr + block_data_offset;

  if (block_data_offset + pLen > shmsize) {
    std::cout << "block_data_offset:" << block_data_offset << ", pLen:" << pLen << ", shmsize:" << shmsize << std::endl;
    return 0;
  }

  int tempSize = blockNum_flag[i] + pLen;

  memcpy(block_data, p, pLen);
  *readLen = pLen;

  if (tempSize > 262144) {
    blockNum_flag[i] = 262144;
    blockNum_flag[i + 1] = tempSize - 262144;
    transfer_to_main->read_position++;
    // std::cout << "i1: " << i << ", blockNum_flag[i]:" << blockNum_flag[i] << ", block_data_offset:" << block_data_offset << ", pLen:" << pLen << ", shmsize:" << shmsize << std::endl;
    if (block_data_offset + pLen == shmsize) {
      transfer_to_main->read_position++;
      // std::cout << "i2: " << i << ", blockNum_flag[i]:" << blockNum_flag[i] << ", block_data_offset:" << block_data_offset << ", pLen:" << pLen << ", shmsize:" << shmsize << std::endl;
    }
    return 1;
  } else {
    blockNum_flag[i] = tempSize;

    if (blockNum_flag[i] == 262144) {
      transfer_to_main->read_position++;
      // std::cout << "i3: " << i << ", blockNum_flag[i]:" << blockNum_flag[i] << ", block_data_offset:" << block_data_offset << ", pLen:" << pLen << ", shmsize:" << shmsize << std::endl;
      return 1;
    }
  }

  if (block_data_offset + pLen == shmsize) {
    transfer_to_main->read_position++;
    // std::cout << "i4: " << i << ", blockNum_flag[i]:" << blockNum_flag[i] << ", block_data_offset:" << block_data_offset << ", pLen:" << pLen << ", shmsize:" << shmsize << std::endl;
  }

  return 1;
}


// ==================================================================================
//				The new dir Multi-process Keystone Decrypt secure dispatch
// ==================================================================================

// get just call shmsize
unsigned long long TheNewDirMultiProcessTEESecureDispatchGetSHMSizeJustCall(int flexible) {
  return (sizeof(int) * flexible) + sizeof(TheNewDirMultiProcessTEESecureDispatchSHMBufferJustCall);
}

// create shm just call
void* the_new_dir_secure_dispatch_ulnoglong_create_shareMemory_just_call(unsigned long long shmsize) {
  int id = shmget(THE_NEW_DIR_SECURE_DISPATCH_SHMKEY_JUST_CALL, shmsize, IPC_CREAT | 0666);
  if (id == -1) {
    printf("%s: \n", __func__);
    perror("Failed to get shared memory");
    exit(-1);
  }

  void* shmaddr = shmat(id, NULL, 0);
  if (shmaddr == (void *)-1) {
    perror("Failed to attach shared memory");
    exit(-1);
  }

  return shmaddr;
}

// create shm transfer file
static void* the_new_dir_secure_dispatch_ulnoglong_create_shareMemory_transfer_file(unsigned long long shmsize, unsigned long long fileCount) {
  // printf("%s: fileCount=%lu\n", __func__, THE_NEW_DIR_SECURE_DISPATCH_SHMKEY_JUST_CALL + fileCount);
  int id = shmget(THE_NEW_DIR_SECURE_DISPATCH_SHMKEY_JUST_CALL + fileCount, shmsize, IPC_CREAT | 0666);
  if (id == -1) {
    printf("%s: \n", __func__);
    perror("Failed to get shared memory");
    exit(-1);
  }

  void* shmaddr = shmat(id, NULL, 0);
  if (shmaddr == (void *)-1) {
    perror("Failed to attach shared memory");
    exit(-1);
  }

  return shmaddr;
}

// init shm just call
void the_new_secure_dispacth_initSHM_just_call(void* shmaddr, int flexible) {
  int *enclave_ready = (int*)shmaddr;
  for (int i = 0; i < flexible; ++i) {
    enclave_ready[i] = 0;
  }

  TheNewDirMultiProcessTEESecureDispatchSHMBufferJustCall *transfer_to_main_just_call = (TheNewDirMultiProcessTEESecureDispatchSHMBufferJustCall*)((char*)shmaddr + (sizeof(int) * flexible));
  transfer_to_main_just_call->fileSize = 0;
  transfer_to_main_just_call->shmReady = 0;
  transfer_to_main_just_call->fileCount = 0;
}

// wait keystone already just call
void the_new_secure_dispatch_waitKeystoneReady_just_call(void *shmaddr, int flexible) {
  int *enclave_ready = (int*)shmaddr;

  for (int i = (flexible -1); i >= 0 ; i--) {
    while(1) {
      if (enclave_ready[i] == 1) {
        break;
      }
    }
  }
}

static unsigned long long THENEWDIRDISPATHfilesize = 0ULL;

// set filesize and create transfer file shm
void* thenewdirsecuredispathSetLength(void *shmaddr, void* blockNum, void* size, int flexible) {
  TheNewDirMultiProcessTEESecureDispatchSHMBufferJustCall *transfer_to_main_just_call = (TheNewDirMultiProcessTEESecureDispatchSHMBufferJustCall*)((char*)shmaddr + (sizeof(int) * flexible));
  // printf("%s, size:%lu\n", __func__, *(unsigned long long *)size);
  if (*(unsigned long long *)size == 0) {
    transfer_to_main_just_call->fileSize = 0;
    transfer_to_main_just_call->fileCount = 0;
    transfer_to_main_just_call->shmReady = 4;
    return NULL;
  }
  // printf("%s, size:%lu\n", __func__, *(unsigned long long *)size);
  THENEWDIRDISPATHfilesize = *(unsigned long long *)size;

  // create transfer file shm and init
  *(unsigned long long *)blockNum = ((*(unsigned long long *)size + 0x3ffff) >> 18);
  int data_offset = (sizeof(TheNewDirMultiProcessTEESecureDispatchSHMBufferTransferFile) + ((*(unsigned long long *)blockNum) * sizeof(int)));
  // printf("%s: fileCount=%lu, size:%ld\n", __func__, transfer_to_main_just_call->fileCount, *(unsigned long long *)size);

  transfer_to_main_just_call->fileCount++;
  transfer_to_main_just_call->fileSize = *(unsigned long long *)size + data_offset;

  void* transfer_keystone = the_new_dir_secure_dispatch_ulnoglong_create_shareMemory_transfer_file(*(unsigned long long *)size + data_offset, transfer_to_main_just_call->fileCount);
  TheNewDirMultiProcessTEESecureDispatchSHMBufferTransferFile *transfer_to_main_file = (TheNewDirMultiProcessTEESecureDispatchSHMBufferTransferFile*)(transfer_keystone);
  transfer_to_main_file->read_position  = 0;
  transfer_to_main_file->dataptr_offset = data_offset;

  int * transfer_to_main_file_blockNum_init = (int *)(((char*)transfer_keystone) + sizeof(TheNewDirMultiProcessTEESecureDispatchSHMBufferTransferFile));

  for (int i = 0; i < *(unsigned long long *)blockNum; ++i) {
    transfer_to_main_file_blockNum_init[i] = 0;
  }

  // printf("%s, size:%lu\n", __func__, *(unsigned long long *)size);
  *(unsigned long long *)size += data_offset;
  // printf("%s, size:%lu\n", __func__, *(unsigned long long *)size);
  transfer_to_main_just_call->shmReady = 1;

  return transfer_keystone;
}

// wait transfer keystone already
void the_new_secure_dispatch_wait_transfer_keystone_ready(void *shmaddr_just_call, int flexible) {
  TheNewDirMultiProcessTEESecureDispatchSHMBufferJustCall *transfer_to_main_just_call = (TheNewDirMultiProcessTEESecureDispatchSHMBufferJustCall*)((char*)shmaddr_just_call + (sizeof(int) * flexible));

  while(1) {
    if (transfer_to_main_just_call->shmReady == 2) {
      break;
    }
  }
}

// write
int the_new_secure_dispatch_write(void *shmaddr, long long shmsize, char* p, int pLen, int* readLen, int flexible) {
  TheNewDirMultiProcessTEESecureDispatchSHMBufferTransferFile *transfer_to_main_file = (TheNewDirMultiProcessTEESecureDispatchSHMBufferTransferFile*)(shmaddr);
  
  int i = transfer_to_main_file->read_position;

  int *blockNum_flag = (int*)((char*)shmaddr + sizeof(TheNewDirMultiProcessTEESecureDispatchSHMBufferTransferFile));

  long long block_data_offset = transfer_to_main_file->dataptr_offset + (i << 18) + blockNum_flag[i];
  char *block_data = (char*)shmaddr + block_data_offset;

  if (block_data_offset + pLen > shmsize) {
    std::cout << "error" << "block_data_offset:" << block_data_offset << ", pLen:" << pLen << ", shmsize:" << shmsize << std::endl;
    return 0;
  }

  int tempSize = blockNum_flag[i] + pLen;

  memcpy(block_data, p, pLen);
  *readLen = pLen;

  if (tempSize > 262144) {
    blockNum_flag[i] = 262144;
    blockNum_flag[i + 1] = tempSize - 262144;
    transfer_to_main_file->read_position++;
    // std::cout << "i1: " << i << ", blockNum_flag[i]:" << blockNum_flag[i] << ", block_data_offset:" << block_data_offset << ", pLen:" << pLen << ", shmsize:" << shmsize << std::endl;
    if (block_data_offset + pLen == shmsize) {
      transfer_to_main_file->read_position++;
      // std::cout << "i2: " << i << ", blockNum_flag[i]:" << blockNum_flag[i] << ", block_data_offset:" << block_data_offset << ", pLen:" << pLen << ", shmsize:" << shmsize << std::endl;
    }
    return 1;
  } else {
    blockNum_flag[i] = tempSize;

    if (blockNum_flag[i] == 262144) {
      transfer_to_main_file->read_position++;
      // std::cout << "i3: " << i << ", blockNum_flag[i]:" << blockNum_flag[i] << ", block_data_offset:" << block_data_offset << ", pLen:" << pLen << ", shmsize:" << shmsize << std::endl;
      return 1;
    }
  }

  if (block_data_offset + pLen == shmsize) {
    transfer_to_main_file->read_position++;
    // std::cout << "i4: " << i << ", blockNum_flag[i]:" << blockNum_flag[i] << ", block_data_offset:" << block_data_offset << ", pLen:" << pLen << ", shmsize:" << shmsize << std::endl;
  }

  return 1;
}

// wati transfer keystone done
void the_new_secure_dispatch_wait_transfer_keystoneDone(void *shmaddr, int flexible) {
  TheNewDirMultiProcessTEESecureDispatchSHMBufferJustCall *transfer_to_main_just_call = (TheNewDirMultiProcessTEESecureDispatchSHMBufferJustCall*)((char*)shmaddr + (sizeof(int) * flexible));
  while(1) {
    if (transfer_to_main_just_call->shmReady == 3) {
      break;
    }
  }
}

// detach transfer file shm
void the_new_secure_dispatch_detach_shareMemory(void* shmaddr) {
  shmdt(shmaddr);
}

// remove transfer file shm
void the_new_secure_dispatch_ulnoglong_remove_shareMemory(unsigned long long shmsize, long long fileCount) {
  int id = shmget(THE_NEW_DIR_SECURE_DISPATCH_SHMKEY_JUST_CALL + fileCount, shmsize, 0666);
  if (id == -1) {
    printf("%s: \n", __func__);
    perror("Failed to get shared memory");
    exit(-1);
  }

  if (shmctl(id, IPC_RMID, NULL) == -1) {
    printf("%s: ", __func__);
    perror("shmctl");
    exit(-1);
  }
}


// ==================================================================================
//				The new dir Keystone Decrypt
// ==================================================================================

// init kjb
void init_keystone_just_ready(KeystoneJustReady *kjb) {
  kjb->keystone_ready = 0;
  kjb->file_ready = 0;
}

RingBuffer* the_new_dir_tempRB = NULL;
KeystoneJustReady* the_new_dir_tempKJB = NULL;
void
the_new_dir_get_filename_wrapper(void* buffer);
void
the_new_dir_ring_buffer_read_wrapper(void* buffer);
char *THENEWDIRKEYSTONEFILENAME = NULL;
void the_new_dir_ipfs_keystone_de(int isDeAES, void *fileName, void* kjb, void* rb) {
  // 需要分配内存并复制字符串，确保释放内存以避免内存泄漏。
  if (fileName != NULL) {

    THENEWDIRKEYSTONEFILENAME = (char*)fileName;

  }

  if (kjb != NULL)
  {
    the_new_dir_tempKJB = (KeystoneJustReady*)kjb;
  }

  if (rb != NULL)
  {
    the_new_dir_tempRB = (RingBuffer*)rb;
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
      enclave.init("thenewdirdeaes", "eyrie-rt", "loader.bin", params);
      break;
  case SM4:
      enclave.init("thenewdirdesm4", "eyrie-rt", "loader.bin", params);
      break;
  case demo:
      enclave.init("hello-native", "eyrie-rt", "loader.bin", params);
      break;
  default:
      std::cout << "the new dir TEE do nothing" << std::endl;
      return;
  }

  enclave.registerOcallDispatch(incoming_call_dispatch);

  /* We must specifically register functions we want to export to the
     enclave. */
  register_call(OCALL_PRINT_STRING, print_string_wrapper);
  register_call(OCALL_GET_FILENAME, the_new_dir_get_filename_wrapper);
  register_call(OCALL_RING_BUFFER_READ, the_new_dir_ring_buffer_read_wrapper);

  edge_call_init_internals(
      (uintptr_t)enclave.getSharedBuffer(), enclave.getSharedBufferSize());

  auto end = std::chrono::steady_clock::now();
  std::chrono::duration<double, std::micro> elapsed = end - start;
  std::cout << "Elapsed time: " << elapsed.count() << " microseconds" << std::endl;

  while(1) {
    if (the_new_dir_tempKJB->keystone_ready == 0) {
      the_new_dir_tempKJB->keystone_ready = 1;
      break;
    }
  }
  std::cout << "enclave run" << std::endl;

  enclave.run();

  // the_new_dir_tempRB->running = 0;

  THENEWDIRKEYSTONEFILENAME = NULL;
  the_new_dir_tempKJB = NULL;
  the_new_dir_tempRB = NULL;

  std::cout << "enclave done" << std::endl;
}

void the_new_dir_keystone_wait_ready(void* kjb) {
  // printf("%s\n", __func__);
  while(1) {
    if (((KeystoneJustReady*)kjb)->keystone_ready == 1) {
      break;
    }
  }
  std::cout << "keystone already" << std::endl;
}

void thenewdirkeystonedecryptSetLength(void *kjb, unsigned long long fileSize) {
  KeystoneJustReady *tempkjb = (KeystoneJustReady*)(kjb);
  // printf("%s, size:%lu\n", __func__, fileSize);
  if (fileSize == 0) {
    tempkjb->file_ready = 4;
    return;
  }
  
  tempkjb->file_ready = 1;

  return;
}

void the_new_dir_wait_keystone_file_ready(void* kjb) {
  while(1) {
    if (((KeystoneJustReady*)kjb)->file_ready == 2) {
      break;
    }
  }
}

void the_new_dir_wait_keystone_file_end(KeystoneJustReady *kjb) {
  while(1) {
    if (kjb->file_ready == 3) {
      break;
    }
  }
}

void
the_new_dir_ring_buffer_read_wrapper(void* buffer) {

  // printf("%s\n", __func__);
  struct edge_call* edge_call = (struct edge_call*)buffer;
  uintptr_t call_args;
  size_t arg_len;
  if (edge_call_args_ptr(edge_call, &call_args, &arg_len) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  if (the_new_dir_tempRB == NULL)
  {
    std::cout << "the_new_dir_tempRB == NULL in the_new_dir_ring_buffer_read_wrapper. the_new_dir_tempRB: " << the_new_dir_tempRB << std::endl;
    return;
  }

  size_t usedSpace = 0;
  size_t size = 0;
  while (ring_buffer_space_used(the_new_dir_tempRB) == 0 && the_new_dir_tempRB->running)
  {
    ;
  }

  if (!the_new_dir_tempRB->running && ring_buffer_space_used(the_new_dir_tempRB) == 0) {
    // free(the_new_dir_tempRB);  // 不释放内存空间，只设置为NULL，方便cgo进行最后的判断
    if (edge_call_setup_wrapped_ret(edge_call, NULL, 0)) {
      edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
    } else {
      edge_call->return_data.call_status = CALL_STATUS_OK;
    }
    the_new_dir_tempKJB->file_ready = 3;
    return;
    // size = 0;
  } else {
    usedSpace = ring_buffer_space_used(the_new_dir_tempRB);
    size = usedSpace < 786432 ? usedSpace : 786432;
    // std::cout << "size :" << size << std::endl;
    // size = (size + 0xf) & ~0xf;
    // std::cout << "size 1 :" << size << std::endl;
  }

  struct edge_data data_wrapper;
  data_wrapper.size = size;
  edge_call_get_offset_from_ptr(
      _shared_start + sizeof(struct edge_call) + sizeof(struct edge_data),
      sizeof(struct edge_data), &data_wrapper.offset);

  int remaining = BUFFER_SIZE - the_new_dir_tempRB->read_pos;
  // // printf("ring data p: %s\n", the_new_dir_tempRB->buffer + the_new_dir_tempRB->read_pos);
  // printf("read wrapper start......\n");
  if (size <= remaining) {
    memcpy(
      (void*)(_shared_start + sizeof(struct edge_call) + sizeof(struct edge_data)),
      (void*)(the_new_dir_tempRB->buffer + the_new_dir_tempRB->read_pos), size);
      the_new_dir_tempRB->read_pos += size;
  } else {
    memcpy(
      (void*)(_shared_start + sizeof(struct edge_call) + sizeof(struct edge_data)),
      (void*)(the_new_dir_tempRB->buffer + the_new_dir_tempRB->read_pos), remaining);
    memcpy(
      (void*)(_shared_start + sizeof(struct edge_call) + sizeof(struct edge_data) + remaining),
      (void*)(the_new_dir_tempRB->buffer), size - remaining);
      the_new_dir_tempRB->read_pos = size - remaining;
  }

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

  return;
}

void
the_new_dir_get_filename_wrapper(void* buffer) {

  struct edge_call* edge_call = (struct edge_call*)buffer;
  uintptr_t call_args;
  size_t arg_len;
  if (edge_call_args_ptr(edge_call, &call_args, &arg_len) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  if (THENEWDIRKEYSTONEFILENAME == NULL) {
    std::cout << "THENEWDIRKEYSTONEFILENAME == NULL in get_filename_wrapper. THENEWDIRKEYSTONEFILENAME: " << THENEWDIRKEYSTONEFILENAME << std::endl;
    return;
  }

  int file_name_len = 0;
  while(1) {
    if (the_new_dir_tempKJB->file_ready == 1) {
      file_name_len = strlen(THENEWDIRKEYSTONEFILENAME) + 1;
      break;
    }
    if (the_new_dir_tempKJB->file_ready == 4) {
      file_name_len = 0;
      break;
    }
  }

  // printf("%s, file_name_len:%d\n", __func__, file_name_len);

  if (edge_call_setup_wrapped_ret(edge_call, (void*)THENEWDIRKEYSTONEFILENAME, file_name_len)) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  } else {
    edge_call->return_data.call_status = CALL_STATUS_OK;
  }

  if (file_name_len != 0) {
    init_ring_buffer(the_new_dir_tempRB);
    the_new_dir_tempKJB->file_ready = 2;
  }

  // printf("%s, file_ready:%d\n", __func__, the_new_dir_tempKJB->file_ready);
  
  return;
}


// 创建共享内存
void *the_new_dir_long_create_shareMemory(long long shmsize){
  int id = shmget(THE_NEW_DIR_MULTI_PROCESS_SHMKEY_JUST_CALL, shmsize, IPC_CREAT | 0666);
  if (id == -1) {
    printf("%s: ", __func__);
    perror("Failed to get shared memory");
    exit(-1);
  }

  void* shmaddr = shmat(id, NULL, 0);
  if (shmaddr == (void *)-1) {
    printf("%s: ", __func__);
    perror("Failed to attach shared memory");
    exit(-1);
  }

  return shmaddr;
}

// 启动keystone之前先初始化内存空间
void theNewDirflexiblecrossInitSHMJustCall(void *shmaddr, int flexible) {
  int *keystone_just_call_ready = (int*)shmaddr;
  for(int i = 0; i < flexible; ++i) {
    keystone_just_call_ready[i] = 0;
  }

  TheNewDirMultiProcessCrossFlexibleSHMBufferJustCall* t = (TheNewDirMultiProcessCrossFlexibleSHMBufferJustCall*)((char*)shmaddr + (sizeof(int) * flexible));
  t->fileSize = 0;
  t->fileCount = 0;

  long long *shmReadyFlag = (long long*)((char*)shmaddr + (sizeof(int) * flexible) + sizeof(TheNewDirMultiProcessCrossFlexibleSHMBufferJustCall));
  for (int i = 0; i < flexible; ++i) {
    shmReadyFlag[i] = 0;
  }
}

// 等待keystone already
void theNewDirflexiblecrosswaitKeystoneReady(void *shmaddr, int flexible) {
  int *keystone_just_call_ready = (int*)shmaddr;

  int flag = 0;
  while(flag == flexible) {
    if (keystone_just_call_ready[flag] == 1) {
      flag++;
    }
  }
  
}


// 创建共享内存
void *the_new_dir_long_create_shareMemory_of_file(long long shmsize, long long fileCount) {
  long long key = THE_NEW_DIR_MULTI_PROCESS_SHMKEY_JUST_CALL + fileCount;
  // printf("%s:, key:%lld, shmsize:%lld\n", __func__, key, shmsize);
  int id = shmget(key, shmsize, IPC_CREAT | 0666);
  if (id == -1) {
    printf("%s: ", __func__);
    printf("shmget failed: %s (errno=%d)\n", strerror(errno), errno);
    perror("Failed to get shared memory");
    exit(-1);
  }

  void* shmaddr = shmat(id, NULL, 0);
  if (shmaddr == (void *)-1) {
    printf("%s: ", __func__);
    perror("Failed to attach shared memory");
    exit(-1);
  }

  return shmaddr;
}

// 等待keystone already
void theNewDirflexiblecrosswaitKeystoneTransferFilesReady(void *shmaddr_just_call, int flexible, void *shmaddr_transfer_file, long long blockNum, long long fileSize, void *fileName) {
  TheNewDirMultiProcessCrossFlexibleSHMBufferJustCall* just_call = (TheNewDirMultiProcessCrossFlexibleSHMBufferJustCall*)((char*)shmaddr_just_call + (sizeof(int) * flexible)); 
  long long *shmReadyFlag = (long long*)((char*)shmaddr_just_call + (sizeof(int) * flexible) + sizeof(TheNewDirMultiProcessCrossFlexibleSHMBufferJustCall));

  // done return
  if (shmaddr_transfer_file == NULL || blockNum == 0 || fileSize == 0 || fileName == NULL) {
    just_call->fileCount = 0;
    just_call->fileSize = 0;
    for (int i = 0; i < flexible; ++i) {
      shmReadyFlag[i] = 4;
    }
    return;
  }

  TheNewDirMultiProcessCrossFlexibleSHMBufferReader* transfer = (TheNewDirMultiProcessCrossFlexibleSHMBufferReader*)(shmaddr_transfer_file); 
  int *transfer_file_number_flag = (int *)(((char*)shmaddr_transfer_file) + sizeof(TheNewDirMultiProcessCrossFlexibleSHMBufferReader));

  transfer->read_position = 0;
  transfer->offset = sizeof(TheNewDirMultiProcessCrossFlexibleSHMBufferReader) + (blockNum * sizeof(int));

  for (int i = 0; i < blockNum; ++i) {
    transfer_file_number_flag[i] = 0;
  }

  just_call->fileCount++;
  just_call->fileSize = fileSize;
  int fileNameLen = strlen((char*)fileName);

  if (fileNameLen > 2048) {
    printf("%s: error. fileNameLen:%d >= 2048\n", fileNameLen);
    just_call->fileName[0] = '\0';
  } else {
    strncpy(just_call->fileName, (char*)fileName, fileNameLen);
    just_call->fileName[fileNameLen] = '\0';
  }

  for (int i = 0; i < flexible; ++i) {
    shmReadyFlag[i] = 1;
  }

  for (int i = 0; i < flexible; ++i) {
    while(1) {
      if (shmReadyFlag[i] == 2) {
        break;
      }
    }
  }
}


int TheNewDirMultiProcessCrossReadFlexible(void* shmaddr, int shmsize, void* data, int len, int* readLen) {
  TheNewDirMultiProcessCrossFlexibleSHMBufferReader* tMPCFSB = (TheNewDirMultiProcessCrossFlexibleSHMBufferReader*)shmaddr;

  unsigned int* src_offset_flag = (unsigned int*)((char*)shmaddr + sizeof(TheNewDirMultiProcessCrossFlexibleSHMBufferReader));
  char* src_offset_data = (char*)shmaddr + tMPCFSB->offset;

  while (src_offset_flag[tMPCFSB->read_position] == 0 && (tMPCFSB->offset > ((tMPCFSB->read_position * 4) + sizeof(TheNewDirMultiProcessCrossFlexibleSHMBufferReader))))
  {
    ;
  }

  if (tMPCFSB->offset <= ((tMPCFSB->read_position * 4) + sizeof(TheNewDirMultiProcessCrossFlexibleSHMBufferReader))) {
    return 0;
  }

  if (src_offset_flag[tMPCFSB->read_position] == 0) {
    printf("Keystone write data error\n");
    return 0;
  }

  *readLen = len > src_offset_flag[tMPCFSB->read_position] ? src_offset_flag[tMPCFSB->read_position] : len;

  memcpy(data, src_offset_data + ((tMPCFSB->read_position) << 18), *readLen);
  tMPCFSB->read_position += 1;

  // printf("read_position:%d\n offset:%d\n", tMPCFSB->read_position, tMPCFSB->offset);

  return 1;
  
}

void theNewDirflexiblecrosswaitKeystoneTransferFilesEnd(void* shmaddr_just_call, int flexible) {
  long long *shmReadyFlag = (long long*)((char*)shmaddr_just_call + (sizeof(int) * flexible) + sizeof(TheNewDirMultiProcessCrossFlexibleSHMBufferJustCall));

  for (int i = 0; i < flexible; ++i) {
    while(1) {
      if (shmReadyFlag[i] == 3) {
        break;
      }
    }
  }
}

// 删除共享内存段
void the_new_dir_flexbile_long_removeShm(long long shmsize, long long fileCount) {
  int id = shmget((THE_NEW_DIR_MULTI_PROCESS_SHMKEY_JUST_CALL+fileCount), shmsize, 0666);
  if (id == -1) {
    perror("Failed to get shared memory");
    exit(-1);
  }

  if (shmctl(id, IPC_RMID, NULL) == -1) {
    perror("shmctl");
    exit(-1);
  }
}

// ==================================================================================
//				The New Dir Keystone Encrypt
// ==================================================================================

RingBuffer* the_new_dir_tempRB_add = NULL;
KeystoneJustReadyAdd* the_new_dir_tempKJB_add = NULL;
void
the_new_dir_get_filename_add_wrapper(void* buffer);
void
the_new_dir_ring_buffer_write_wrapper(void* buffer);
char *THENEWDIRKEYSTONEFILENAMEADD = NULL;
void the_new_dir_ipfs_keystone(int isAES, void* kjb, void* rb) {
  // 需要分配内存并复制字符串，确保释放内存以避免内存泄漏。

  if (kjb != NULL)
  {
    the_new_dir_tempKJB_add = (KeystoneJustReadyAdd*)kjb;
  }

  if (rb != NULL)
  {
    the_new_dir_tempRB_add = (RingBuffer*)rb;
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
      enclave.init("thenewdiraes", "eyrie-rt", "loader.bin", params);
      break;
  case SM4:
      enclave.init("thenewdirsm4", "eyrie-rt", "loader.bin", params);
      break;
  case demo:
      enclave.init("hello-native", "eyrie-rt", "loader.bin", params);
      break;
  default:
      std::cout << "the new dir TEE do nothing" << std::endl;
      return;
  }

  enclave.registerOcallDispatch(incoming_call_dispatch);

  /* We must specifically register functions we want to export to the
     enclave. */
  register_call(OCALL_PRINT_STRING, print_string_wrapper);
  register_call(OCALL_GET_FILENAME, the_new_dir_get_filename_add_wrapper);
  register_call(OCALL_RING_BUFFER_WRITE, the_new_dir_ring_buffer_write_wrapper);

  edge_call_init_internals(
      (uintptr_t)enclave.getSharedBuffer(), enclave.getSharedBufferSize());

  auto end = std::chrono::steady_clock::now();
  std::chrono::duration<double, std::micro> elapsed = end - start;
  std::cout << "Elapsed time: " << elapsed.count() << " microseconds" << std::endl;

  while(1) {
    if (the_new_dir_tempKJB_add->keystone_ready == 0) {
      the_new_dir_tempKJB_add->keystone_ready = 1;
      break;
    }
  }
  std::cout << "enclave run" << std::endl;

  enclave.run();

  // the_new_dir_tempRB_add->running = 0;

  THENEWDIRKEYSTONEFILENAMEADD = NULL;
  the_new_dir_tempKJB_add = NULL;
  the_new_dir_tempRB_add = NULL;

  std::cout << "enclave done" << std::endl;
}

void
the_new_dir_get_filename_add_wrapper(void* buffer) {

  struct edge_call* edge_call = (struct edge_call*)buffer;
  uintptr_t call_args;
  size_t arg_len;
  if (edge_call_args_ptr(edge_call, &call_args, &arg_len) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  if (the_new_dir_tempKJB_add == NULL) {
    std::cout << "the_new_dir_tempKJB_add != NULL in the_new_dir_get_filename_add_wrapper. the_new_dir_tempKJB_add: " << the_new_dir_tempKJB_add << std::endl;
    return;
  }

  if (THENEWDIRKEYSTONEFILENAMEADD != NULL) {
    std::cout << "THENEWDIRKEYSTONEFILENAMEADD != NULL in the_new_dir_get_filename_add_wrapper. THENEWDIRKEYSTONEFILENAMEADD: " << THENEWDIRKEYSTONEFILENAMEADD << std::endl;
    return;
  }

  THENEWDIRKEYSTONEFILENAMEADD = the_new_dir_tempKJB_add->fileName;

  int file_name_len = 0;
  while(1) {
    if (the_new_dir_tempKJB_add->file_ready == 1) {
      file_name_len = strlen(THENEWDIRKEYSTONEFILENAMEADD) + 1;
      break;
    }
    if (the_new_dir_tempKJB_add->file_ready == 4) {
      file_name_len = 0;
      break;
    }
  }

  // printf("%s, file_name_len:%d\n", __func__, file_name_len);

  if (edge_call_setup_wrapped_ret(edge_call, (void*)THENEWDIRKEYSTONEFILENAMEADD, file_name_len)) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  } else {
    edge_call->return_data.call_status = CALL_STATUS_OK;
  }

  if (file_name_len != 0) {
    init_ring_buffer(the_new_dir_tempRB_add);
    the_new_dir_tempKJB_add->file_ready = 2;
  }

  // printf("%s, file_ready:%d\n", __func__, the_new_dir_tempKJB_add->file_ready);
  
  return;
}

void
the_new_dir_ring_buffer_write_wrapper(void* buffer) {

  struct edge_call* edge_call = (struct edge_call*)buffer;
  uintptr_t call_args;
  size_t arg_len;
  if (edge_call_args_ptr(edge_call, &call_args, &arg_len) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  if (the_new_dir_tempRB_add == NULL)
  {
    std::cout << "the_new_dir_tempRB_add == NULL in the_new_dir_ring_buffer_write_wrapper. the_new_dir_tempRB_add: " << the_new_dir_tempRB_add << std::endl;
    return;
  }

  if (arg_len > 0) {
    ring_buffer_write(the_new_dir_tempRB_add, (char *)call_args, arg_len);
  } else if (arg_len == 0) {
    the_new_dir_tempRB_add->running = 0;
    the_new_dir_tempKJB_add->file_ready = 3;
    THENEWDIRKEYSTONEFILENAMEADD = NULL;
  }

  edge_call->return_data.call_status = CALL_STATUS_OK;

  return;
}

// init kjb
void init_keystone_just_ready_add(KeystoneJustReadyAdd *kjb) {
  kjb->keystone_ready = 0;
  kjb->file_ready = 0;
  kjb->fileName[0] = '\0';
}

void the_new_dir_keystone_wait_ready_add(void* kjb) {
  // printf("%s\n", __func__);
  while(1) {
    if (((KeystoneJustReadyAdd*)kjb)->keystone_ready == 1) {
      break;
    }
  }
  std::cout << "keystone already" << std::endl;
}

// 等待keystone already
void theNewDirKeystoneTransferFilesReady(void *kjb, long long fileSize, void *fileName) {
  KeystoneJustReadyAdd* just_call = (KeystoneJustReadyAdd*)(kjb); 

  // done return
  if (fileSize == 0 || fileName == NULL) {
    just_call->file_ready = 4;
    just_call->fileName[0] = '\0';
    return;
  }

  int fileNameLen = strlen((char*)fileName);

  if (fileNameLen >= 2048) {
    printf("%s: error. fileNameLen:%d >= 2048\n", fileNameLen);
    just_call->fileName[0] = '\0';
  } else {
    strncpy(just_call->fileName, (char*)fileName, fileNameLen);
    just_call->fileName[fileNameLen] = '\0';
  }

  just_call->file_ready = 1;
  while(1) {
    if (just_call->file_ready == 2) {
      break;
    }
  }
}

void the_new_dir_wait_keystone_file_end_add(KeystoneJustReadyAdd *kjb, RingBuffer* rb) {
  while(1) {
    if (kjb->file_ready == 3) {
      rb->read_pos = 0;
      rb->write_pos = 0;
      break;
    }
  }
}
