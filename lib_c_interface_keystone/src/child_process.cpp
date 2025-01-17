#include <edge_call.h>
#include <keystone.h>
#include "ipfs_keystone.h"
#include <iostream>
#include <chrono>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h>

#define SHMKEY  241227
int SHMSIZE = 0;
char *shm = NULL;
HalfPartSHMBuffer* shmpb = NULL;
void* shmpb_offset_data = NULL;

#define OCALL_PRINT_STRING          1
#define OCALL_PB_GET_FILENAMESIZE   5
#define OCALL_PB_BUFFER_WRITE       7

unsigned long print_string(char* str);
void print_string_wrapper(void* buffer);
void get_pb_filenamesize_wrapper(void* buffer);
void pb_buffer_write_wrapper(void* buffer);

MultiFile* MULTIADDFILENAMEPB = NULL;

int main(int argc, char *argv[]) {
    if (argc != 6) {
        printf("Usage: %s <is_aes> <shm_size> <file_path> <start_offset> <end_offset>\n", argv[0]);
        return 0;
    }

    int isAES = atoi(argv[1]);
    SHMSIZE = atoi(argv[2]);
    const char *file_path = argv[3];
    int start_offset = atoi(argv[4]);
    int end_offset = atoi(argv[5]);

    MULTIADDFILENAMEPB = (MultiFile*)malloc(sizeof(MultiFile));
    if (MULTIADDFILENAMEPB == NULL) {
        printf("malloc MULTIADDFILENAMEPB memory error\n");
        return 0;
    }

    int fileNameLen = strlen(file_path) + 1;
    if (fileNameLen > 20) {
        printf("fileName is too long \n");
        free(MULTIADDFILENAMEPB);
        MULTIADDFILENAMEPB = NULL;
        return 0;
    }

    memcpy(MULTIADDFILENAMEPB->fileName, file_path, fileNameLen);
    MULTIADDFILENAMEPB->offset = start_offset;
    MULTIADDFILENAMEPB->maxspace = end_offset;

    // 创建共享内存，并设置共享内存开始结构
    // 创建共享内存
    int shmid = shmget(SHMKEY, SHMSIZE, 0666);
    if (shmid == -1) {
        perror("Failed to get shared memory");
        return 0;
    }

    shm = (char*)shmat(shmid, NULL, 0);
    if (shm == (char *)-1) {
        perror("Failed to attach shared memory");
        return 1;
    }

    // 设置共享内存结构,并初始化
    MultiProcessSHMBuffer* tempmpshb = (MultiProcessSHMBuffer*)shm;
    if (start_offset == 0) {
        shmpb = &tempmpshb->qpb;
    } else {
        shmpb = &tempmpshb->hpb;
    }

    shmpb_offset_data = (void*)(shm + sizeof(MultiProcessSHMBuffer) + start_offset);
    shmpb->MaxSpace = end_offset;
    shmpb->running = 1;
    shmpb->read_pos = 0;
    shmpb->write_pos = 0;

    // 获取当前时间点
    auto start = std::chrono::steady_clock::now();

    Keystone::Enclave enclave;
    Keystone::Params params;

    params.setFreeMemSize(256 * 1024 * 1024);
    params.setUntrustedSize(2 * 1024 * 1024);

    switch (isAES)
    {
    case AES:
        enclave.init("multiaes", "eyrie-rt", "loader.bin", params);
        break;
    case SM4:
        enclave.init("multism4", "eyrie-rt", "loader.bin", params);
        break;
    case demo:
        enclave.init("hello-native", "eyrie-rt", "loader.bin", params);
        break;
    default:
        std::cout << "multiTEE do nothing" << std::endl;
        return 0;
    }

    enclave.registerOcallDispatch(incoming_call_dispatch);

    /* We must specifically register functions we want to export to the
       enclave. */
    register_call(OCALL_PRINT_STRING, print_string_wrapper);
    register_call(OCALL_PB_GET_FILENAMESIZE, get_pb_filenamesize_wrapper);
    register_call(OCALL_PB_BUFFER_WRITE, pb_buffer_write_wrapper);

    edge_call_init_internals(
        (uintptr_t)enclave.getSharedBuffer(), enclave.getSharedBufferSize());

    // 设置 Keystone already
    tempmpshb->offset = sizeof(MultiProcessSHMBuffer);

    auto end = std::chrono::steady_clock::now();
    std::chrono::duration<double, std::micro> elapsed = end - start;
    std::cout << "Elapsed time: " << elapsed.count() << " microseconds" << std::endl;

    enclave.run();

    // 设置共享内存结束标志,并释放内存
    // 设置qpb 或者 hpb结束，标志该pb读取数据完毕
    shmpb->running = 0;
    shmpb_offset_data = NULL;
    shmpb = NULL;
    // 断开连接，由go释放内存
    shmdt(shm);
    shm = NULL;



    if (MULTIADDFILENAMEPB != NULL) {
        free(MULTIADDFILENAMEPB);
        MULTIADDFILENAMEPB = NULL;
    }

    if (start_offset == 0)
        std::cout << "QPB enclave done" << std::endl;
    else 
        std::cout << "HPB enclave done" << std::endl;
    return 0;
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

void get_pb_filenamesize_wrapper(void* buffer) {

  struct edge_call* edge_call = (struct edge_call*)buffer;
  uintptr_t call_args;
  size_t arg_len;
  if (edge_call_args_ptr(edge_call, &call_args, &arg_len) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  if (MULTIADDFILENAMEPB == NULL) {
    std::cout << "MULTIADDFILENAMEPB == NULL in get_pb_filenamesize_wrapper. MULTIADDFILENAMEPB: " << MULTIADDFILENAMEPB << std::endl;
    return;
  }

  if (edge_call_setup_wrapped_ret(edge_call, (void*)MULTIADDFILENAMEPB, sizeof(MultiFile))) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  } else {
    edge_call->return_data.call_status = CALL_STATUS_OK;
  }
  
  return;
}

int pb_buffer_write(const char *data, size_t length) {
  if (shmpb->MaxSpace - shmpb->write_pos < length)
  {
    printf("write buffer error, pb space is not enough\n");
    return -1;
  }
  
  memcpy((void*)((char*)shmpb_offset_data + shmpb->write_pos), data, length);
  shmpb->write_pos += length;

  return length;
  
}


void pb_buffer_write_wrapper(void* buffer) {
    struct edge_call* edge_call = (struct edge_call*)buffer;
    uintptr_t call_args;
    size_t arg_len;
    if (edge_call_args_ptr(edge_call, &call_args, &arg_len) != 0) {
        edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
        return;
    }

    if (shmpb_offset_data == NULL) {
        std::cout << "shmpb_offset_data == NULL in pb_buffer_write_wrapper. shmpb_offset_data: " << shmpb_offset_data << std::endl;
        return;
    }

    if (arg_len >= 0) {
        if (pb_buffer_write((char *)call_args, arg_len) >= 0) {
            edge_call->return_data.call_status = CALL_STATUS_OK;
            return;
        }
    }

    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;

}

