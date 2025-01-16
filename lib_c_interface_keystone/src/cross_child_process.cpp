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
unsigned int* shmpb_offset_flag = NULL;
long long count_POSITION = 0;

#define OCALL_PRINT_STRING          1
#define OCALL_CR_GET_FILENAMESIZE   5
#define OCALL_CR_BUFFER_WRITE       7

unsigned long print_string(char* str);
void print_string_wrapper(void* buffer);
void get_cr_filenamesize_wrapper(void* buffer);
void cr_buffer_write_wrapper(void* buffer);

MultiCrossFile* MULTIADDFILENAMECR = NULL;

int main(int argc, char *argv[]) {
    if (argc != 5) {
        printf("Usage: %s <is_aes> <shm_size> <file_path> <start_offset>\n", argv[0]);
        return 0;
    }

    int isAES = atoi(argv[1]);
    SHMSIZE = atoi(argv[2]);
    const char *file_path = argv[3];
    long long start_offset = atoi(argv[4]);

    MULTIADDFILENAMECR = (MultiCrossFile*)malloc(sizeof(MultiCrossFile));
    if (MULTIADDFILENAMECR == NULL) {
        printf("malloc MULTIADDFILENAMECR memory error\n");
        return 0;
    }

    int fileNameLen = strlen(file_path) + 1;
    if (fileNameLen > 50) {
        printf("fileName is too long \n");
        free(MULTIADDFILENAMECR);
        MULTIADDFILENAMECR = NULL;
        return 0;
    }

    memcpy(MULTIADDFILENAMECR->fileName, file_path, fileNameLen);
    MULTIADDFILENAMECR->start_offset = start_offset;

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
    MultiProcessCrossSHMBuffer* tempmpshb = (MultiProcessCrossSHMBuffer*)shm;
    shmpb_offset_flag = (unsigned int*)(shm + sizeof(MultiProcessCrossSHMBuffer));
    shmpb_offset_data = (void*)(shm + sizeof(MultiProcessCrossSHMBuffer) + tempmpshb->offset);
    count_POSITION = start_offset;
 

    // 获取当前时间点
    auto start = std::chrono::steady_clock::now();

    Keystone::Enclave enclave;
    Keystone::Params params;

    params.setFreeMemSize(256 * 1024 * 1024);
    params.setUntrustedSize(2 * 1024 * 1024);

    switch (isAES)
    {
    case AES:
        enclave.init("crmultiaes", "eyrie-rt", "loader.bin", params);
        break;
    case SM4:
        enclave.init("crmultism4", "eyrie-rt", "loader.bin", params);
        break;
    case demo:
        enclave.init("hello-native", "eyrie-rt", "loader.bin", params);
        break;
    default:
        std::cout << "crmultiTEE do nothing" << std::endl;
        return 0;
    }

    enclave.registerOcallDispatch(incoming_call_dispatch);

    /* We must specifically register functions we want to export to the
       enclave. */
    register_call(OCALL_PRINT_STRING, print_string_wrapper);
    register_call(OCALL_CR_GET_FILENAMESIZE, get_cr_filenamesize_wrapper);
    register_call(OCALL_CR_BUFFER_WRITE, cr_buffer_write_wrapper);

    edge_call_init_internals(
        (uintptr_t)enclave.getSharedBuffer(), enclave.getSharedBufferSize());

    // 设置 Keystone already
    if (start_offset == 0) {
      tempmpshb->ready1 = 1;
    } else if (start_offset == 1) {
      tempmpshb->ready2 = 1;
    }


    auto end = std::chrono::steady_clock::now();
    std::chrono::duration<double, std::micro> elapsed = end - start;
    std::cout << "Elapsed time: " << elapsed.count() << " microseconds" << std::endl;

    enclave.run();

    // 设置共享内存结束标志,并释放内存
    // 设置qpb 或者 hpb结束，标志该pb读取数据完毕
    shmpb_offset_data = NULL;
    shmpb_offset_flag = NULL;
    // 设置 Keystone Done
    if (start_offset == 0) {
      tempmpshb->ready1 = 0;
    } else if (start_offset == 1) {
      tempmpshb->ready2 = 0;
    }

    // 断开连接，由go释放内存
    shmdt(shm);
    shm = NULL;



    if (MULTIADDFILENAMECR != NULL) {
        free(MULTIADDFILENAMECR);
        MULTIADDFILENAMECR = NULL;
    }

    if (start_offset == 0)
        std::cout << "0 enclave done" << std::endl;
    else 
        std::cout << "1 enclave done" << std::endl;
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

void get_cr_filenamesize_wrapper(void* buffer) {

  struct edge_call* edge_call = (struct edge_call*)buffer;
  uintptr_t call_args;
  size_t arg_len;
  if (edge_call_args_ptr(edge_call, &call_args, &arg_len) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  if (MULTIADDFILENAMECR == NULL) {
    std::cout << "MULTIADDFILENAMECR == NULL in get_cr_filenamesize_wrapper. MULTIADDFILENAMECR: " << MULTIADDFILENAMECR << std::endl;
    return;
  }

  if (edge_call_setup_wrapped_ret(edge_call, (void*)MULTIADDFILENAMECR, sizeof(MultiCrossFile))) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  } else {
    edge_call->return_data.call_status = CALL_STATUS_OK;
  }
  
  return;
}

int cr_buffer_write(const char *data, size_t length) {

  MultiProcessCrossSHMBuffer* tempmpshb = (MultiProcessCrossSHMBuffer*)shm;
  if (tempmpshb->offset <= count_POSITION) {
    printf("write cross buffer error, count_POSITION is error\n");
    return -1;
  }

  if (length > 0x40000) {
    printf("write cross buffer error, data length is greater than 256*1024 \n");
    return -1;
  }
  
  memcpy((void*)((char*)shmpb_offset_data + (count_POSITION << 18)), data, length);
  shmpb_offset_flag[count_POSITION] = length;
  count_POSITION += 2;

  return length;
  
}


void cr_buffer_write_wrapper(void* buffer) {
    struct edge_call* edge_call = (struct edge_call*)buffer;
    uintptr_t call_args;
    size_t arg_len;
    if (edge_call_args_ptr(edge_call, &call_args, &arg_len) != 0) {
        edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
        return;
    }

    if (shmpb_offset_data == NULL) {
        std::cout << "shmpb_offset_data == NULL in cr_buffer_write_wrapper. shmpb_offset_data: " << shmpb_offset_data << std::endl;
        return;
    }

    if (shmpb_offset_flag == NULL) {
        std::cout << "shmpb_offset_flag == NULL in cr_buffer_write_wrapper. shmpb_offset_flag: " << shmpb_offset_flag << std::endl;
        return;
    }

    if (arg_len >= 0) {
        if (cr_buffer_write((char *)call_args, arg_len) >= 0) {
            edge_call->return_data.call_status = CALL_STATUS_OK;
            return;
        }
    }

    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;

}

