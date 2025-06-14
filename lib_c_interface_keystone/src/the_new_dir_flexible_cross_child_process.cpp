#include <edge_call.h>
#include <keystone.h>
#include "ipfs_keystone.h"
#include <iostream>
#include <chrono>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h>

#define THE_NEW_DIR_MULTI_PROCESS_SHMKEY_JUST_CALL (250611)
int SHMSIZE = 0;
int NUM_Flexible = 0;
char *shm = NULL;
TheNewDirMultiProcessCrossFlexibleSHMBufferJustCall* TNDMPCFSHMB_JUST_CALL = NULL;

char *shmfileaddr = NULL;
TheNewDirMultiProcessCrossFlexibleSHMBufferReader* TNDMPCFSHMB_READER = NULL;
void* shmpb_offset_data = NULL;
unsigned int* shmpb_offset_flag = NULL;
long long count_POSITION = 0;

#define OCALL_PRINT_STRING          1
#define OCALL_CR_GET_MS             5
#define OCALL_CR_BUFFER_WRITE       7
#define OCALL_CR_GET_FILENAME_PATH  9

unsigned long print_string(char* str);
void print_string_wrapper(void* buffer);
void get_cr_ms_wrapper(void* buffer);
void cr_buffer_write_wrapper(void* buffer);
void get_cr_filename_path_wrapper(void* buffer);

TheNewDirMultiCrossFlexibleFile* MULTIADDFILENAMECR = NULL;

int main(int argc, char *argv[]) {
    if (argc != 5) {
        printf("Usage: %s <is_aes> <shm_size> <start_offset> <flexible>\n", argv[0]);
        return 0;
    }

    int isAES = atoi(argv[1]);
    SHMSIZE = atoi(argv[2]);
    long long start_offset = atoi(argv[3]);
    int flexible = atoi(argv[4]);

    // printf("<is_aes>: %d <shm_size>:%d <file_path>:%s <start_offset>:%d\n", isAES, SHMSIZE, file_path, start_offset);

    MULTIADDFILENAMECR = (TheNewDirMultiCrossFlexibleFile*)malloc(sizeof(TheNewDirMultiCrossFlexibleFile));
    if (MULTIADDFILENAMECR == NULL) {
        printf("malloc MULTIADDFILENAMECR memory error\n");
        return 0;
    }

    MULTIADDFILENAMECR->start_offset = start_offset;  
    MULTIADDFILENAMECR->numberKeystone = flexible;  

    NUM_Flexible = flexible;

    // 创建共享内存，并设置共享内存开始结构
    // 创建共享内存
    int shmid = shmget(THE_NEW_DIR_MULTI_PROCESS_SHMKEY_JUST_CALL, SHMSIZE, 0666);
    if (shmid == -1) {
        perror("Failed to get shared memory");
        return 0;
    }

    shm = (char*)shmat(shmid, NULL, 0);
    if (shm == (char *)-1) {
        perror("Failed to attach shared memory");
        return 1;
    }

    // printf("test shm1\n");

    // 设置共享内存结构,并初始化
    int *keystone_just_call_ready = (int*)shm;
    TNDMPCFSHMB_JUST_CALL = (TheNewDirMultiProcessCrossFlexibleSHMBufferJustCall*)(shm + (flexible * sizeof(int)));
    TNDMPCFSHMB_READER = NULL;
    shmpb_offset_flag = NULL;
    shmpb_offset_data = NULL;
    count_POSITION = 0;
 
    // printf("test shm\n");

    // 获取当前时间点
    auto start = std::chrono::steady_clock::now();

    Keystone::Enclave enclave;
    Keystone::Params params;

    params.setFreeMemSize(256 * 1024 * 1024);
    params.setUntrustedSize(2 * 1024 * 1024);

    switch (isAES)
    {
    case AES:
        enclave.init("thenewdirflexiblecrmultiaes", "eyrie-rt", "loader.bin", params);
        break;
    case SM4:
        enclave.init("thenewdirflexiblecrmultism4", "eyrie-rt", "loader.bin", params);
        break;
    case demo:
        enclave.init("hello-native", "eyrie-rt", "loader.bin", params);
        break;
    default:
        std::cout << "thenewdirflexiblecrmultiTEE do nothing" << std::endl;
        return 0;
    }

    enclave.registerOcallDispatch(incoming_call_dispatch);

    /* We must specifically register functions we want to export to the
       enclave. */
    register_call(OCALL_PRINT_STRING, print_string_wrapper);
    register_call(OCALL_CR_GET_MS, get_cr_ms_wrapper);
    register_call(OCALL_CR_BUFFER_WRITE, cr_buffer_write_wrapper);
    register_call(OCALL_CR_GET_FILENAME_PATH, get_cr_filename_path_wrapper);

    edge_call_init_internals(
        (uintptr_t)enclave.getSharedBuffer(), enclave.getSharedBufferSize());

    // 设置 Keystone already
    keystone_just_call_ready[start_offset] = 1;

    auto end = std::chrono::steady_clock::now();
    std::chrono::duration<double, std::micro> elapsed = end - start;
    std::cout << "Elapsed time: " << elapsed.count() << " microseconds" << std::endl;

    enclave.run();

    // 设置共享内存结束标志,并释放内存
    // 设置qpb 或者 hpb结束，标志该pb读取数据完毕
    shmpb_offset_data = NULL;
    shmpb_offset_flag = NULL;
    // 设置 Keystone Done
    keystone_just_call_ready[start_offset] = 0;

    // 断开连接，由go释放内存
    shmdt(shm);
    shm = NULL;
    TNDMPCFSHMB_JUST_CALL = NULL;



    if (MULTIADDFILENAMECR != NULL) {
        free(MULTIADDFILENAMECR);
        MULTIADDFILENAMECR = NULL;
    }

    std::cout << start_offset << " enclave done" << std::endl;

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

void get_cr_ms_wrapper(void* buffer) {

  struct edge_call* edge_call = (struct edge_call*)buffer;
  uintptr_t call_args;
  size_t arg_len;
  if (edge_call_args_ptr(edge_call, &call_args, &arg_len) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  if (MULTIADDFILENAMECR == NULL) {
    std::cout << "MULTIADDFILENAMECR == NULL in get_cr_ms_wrapper. MULTIADDFILENAMECR: " << MULTIADDFILENAMECR << std::endl;
    return;
  }

  if (edge_call_setup_wrapped_ret(edge_call, (void*)MULTIADDFILENAMECR, sizeof(MultiCrossFlexibleFile))) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  } else {
    edge_call->return_data.call_status = CALL_STATUS_OK;
  }
  
  return;
}

int cr_buffer_write(const char *data, size_t length) {

  if (length == 0) {
    shmdt(shmfileaddr);
    shmfileaddr = NULL;
    TNDMPCFSHMB_READER = NULL;
    shmpb_offset_data = NULL;
    shmpb_offset_flag = NULL;
    count_POSITION = 0;
    long long *shmFileReady = (long long*)(shm + (sizeof(int) * NUM_Flexible) + sizeof(TheNewDirMultiProcessCrossFlexibleSHMBufferJustCall));
    shmFileReady[MULTIADDFILENAMECR->start_offset] = 3;
    return 1;
  }

  if (TNDMPCFSHMB_READER->offset <= count_POSITION << 2) {
    printf("write cross buffer error, count_POSITION is error\n");
    return -1;
  }

  if (length > 0x40000) {
    printf("write cross buffer error, data length is greater than 256*1024 \n");
    return -1;
  }
  
  // printf("count_POSITION:%d\n", count_POSITION);
  memcpy((void*)((char*)shmpb_offset_data + (count_POSITION << 18)), data, length);
  shmpb_offset_flag[count_POSITION] = length;
  count_POSITION += NUM_Flexible;

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

    if (TNDMPCFSHMB_READER == NULL) {
        std::cout << "TNDMPCFSHMB_READER == NULL in cr_buffer_write_wrapper. TNDMPCFSHMB_READER: " << TNDMPCFSHMB_READER << std::endl;
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


void get_cr_filename_path_wrapper(void* buffer) {

  struct edge_call* edge_call = (struct edge_call*)buffer;
  uintptr_t call_args;
  size_t arg_len;
  if (edge_call_args_ptr(edge_call, &call_args, &arg_len) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  if (TNDMPCFSHMB_JUST_CALL == NULL) {
    std::cout << "TNDMPCFSHMB_JUST_CALL == NULL in get_cr_filename_path_wrapper. TNDMPCFSHMB_JUST_CALL: " << TNDMPCFSHMB_JUST_CALL << std::endl;
    return;
  }

  if (MULTIADDFILENAMECR == NULL) {
    std::cout << "MULTIADDFILENAMECR == NULL in get_cr_filename_path_wrapper. MULTIADDFILENAMECR: " << MULTIADDFILENAMECR << std::endl;
    return;
  }

  int fileNameLen = 0;
  long long *shmFileReady = (long long*)(shm + (sizeof(int) * NUM_Flexible) + sizeof(TheNewDirMultiProcessCrossFlexibleSHMBufferJustCall));
  while(1) {
    if (shmFileReady[MULTIADDFILENAMECR->start_offset] == 1) {
      fileNameLen = (strlen(TNDMPCFSHMB_JUST_CALL->fileName) + 1);
      int shmid = shmget(THE_NEW_DIR_MULTI_PROCESS_SHMKEY_JUST_CALL + (TNDMPCFSHMB_JUST_CALL->fileCount), TNDMPCFSHMB_JUST_CALL->fileSize, 0666);
      if (shmid == -1) {
          perror("Failed to get shared memory");
          return;
      }

      char *shmaddr = (char*)shmat(shmid, NULL, 0);
      if (shmaddr == (char *)-1) {
          perror("Failed to attach shared memory");
          return;
      }
      shmfileaddr = shmaddr;
      TNDMPCFSHMB_READER = (TheNewDirMultiProcessCrossFlexibleSHMBufferReader*)shmfileaddr;
      shmpb_offset_flag = (unsigned int*)(shmfileaddr + sizeof(TheNewDirMultiProcessCrossFlexibleSHMBufferReader));
      shmpb_offset_data = (void*)(shmfileaddr + TNDMPCFSHMB_READER->offset);
      count_POSITION = MULTIADDFILENAMECR->start_offset;
      break;
    }

    if (shmFileReady[MULTIADDFILENAMECR->start_offset] == 4) {
      fileNameLen = 0;
      break;
    }
  }

  if (edge_call_setup_wrapped_ret(edge_call, (void*)(TNDMPCFSHMB_JUST_CALL->fileName), fileNameLen)) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  } else {
    edge_call->return_data.call_status = CALL_STATUS_OK;
  }

  if (fileNameLen != 0) {
    shmFileReady[MULTIADDFILENAMECR->start_offset] = 2;
  }
  
  return;
}
