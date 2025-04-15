#include <edge_call.h>
#include <keystone.h>
#include "ipfs_keystone.h"
#include <iostream>
#include <chrono>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h>

#define dispath_shmKey 250227
int SHMSIZE = 0;
char *shm = NULL;
MultiProcessTEEDispatchSHMBuffer* tempmpshb = NULL;
// 数据存放的起始位置
void* shmpb_offset_data = NULL;
// 数据是否被取走
unsigned int* shmpb_offset_flag = NULL;
// 读取的位置i
long long count_POSITION = 0;

#define OCALL_PRINT_STRING                  1
#define OCALL_DISPATH_GET                   5
#define OCALL_DISPATH_GET_BUFFER_READ       7

unsigned long print_string(char* str);
void print_string_wrapper(void* buffer);
void get_dispath_get_wrapper(void* buffer);
void dispath_buffer_read_wrapper(void* buffer);

MultiDispath* MULTIDISPATH = NULL;

int main(int argc, char *argv[]) {
    if (argc != 5) {
        printf("Usage: %s <is_aes> <shm_size> <start_offset> <flexible>\n", argv[0]);
        return 0;
    }

    int isAES = atoi(argv[1]);
    SHMSIZE = atoi(argv[2]);
    long long start_offset = atoi(argv[3]);
    int flexible = atoi(argv[4]);

    MULTIDISPATH = (MultiDispath*)malloc(sizeof(MultiDispath));
    if (MULTIDISPATH == NULL) {
        printf("malloc MULTIDISPATH memory error\n");
        return 0;
    }

    MULTIDISPATH->start_offset = start_offset;  
    MULTIDISPATH->numberKeystone = flexible;
    // NUMflexible = flexible;

    // 创建共享内存，并设置共享内存开始结构
    // 创建共享内存
    int shmid = shmget(dispath_shmKey+start_offset, SHMSIZE, 0666);
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
    tempmpshb = (MultiProcessTEEDispatchSHMBuffer*)shm;
    shmpb_offset_flag = (unsigned int*)(shm + sizeof(MultiProcessTEEDispatchSHMBuffer));
    shmpb_offset_data = (void*)(shm + sizeof(MultiProcessTEEDispatchSHMBuffer) + tempmpshb->offset);
    count_POSITION = 0;
 
    // 获取当前时间点
    auto start = std::chrono::steady_clock::now();

    Keystone::Enclave enclave;
    Keystone::Params params;

    params.setFreeMemSize(256 * 1024 * 1024);
    params.setUntrustedSize(2 * 1024 * 1024);
    params.setYXms(1);
    params.setYXShareTrustedMemSize(1*1024*1024);

    // char maeseappName[] = "mdemultiaes";
    // char saeseappName[] = "sdemultiaes";
    // char msm4eappName[] = "mdemultism4";
    // char ssm4eappName[] = "sdemultism4";

    // char *aeseappName = NULL;
    // char *sm4eappName = NULL;

    // if (start_offset == 0) {
    //   aeseappName = maeseappName;
    //   sm4eappName = msm4eappName;
    // } else {
    //   aeseappName = saeseappName;
    //   sm4eappName = ssm4eappName;
    // }

    char aeseappName[] = "multideaes";
    char sm4eappName[] = "multidesm4";

    char *eappName = NULL;

    std::cout << "host init start" << std::endl;

    switch (isAES)
    {
    case AES:
        eappName = aeseappName;
        enclave.init(eappName, "eyrie-rt", "loader.bin", params);
        break;
    case SM4:
        eappName = sm4eappName;
        enclave.init(eappName, "eyrie-rt", "loader.bin", params);
        break;
    case demo:
        enclave.init("hello-native", "eyrie-rt", "loader.bin", params);
        break;
    default:
        std::cout << "demultiTEE do nothing" << std::endl;
        return 0;
    }

    std::cout << "host init end" << std::endl;

    enclave.registerOcallDispatch(incoming_call_dispatch);

    /* We must specifically register functions we want to export to the
       enclave. */
    register_call(OCALL_PRINT_STRING, print_string_wrapper);
    register_call(OCALL_DISPATH_GET, get_dispath_get_wrapper);
    register_call(OCALL_DISPATH_GET_BUFFER_READ, dispath_buffer_read_wrapper);

    edge_call_init_internals(
        (uintptr_t)enclave.getSharedBuffer(), enclave.getSharedBufferSize());

    // 设置 Keystone already
    tempmpshb->ready = 1;

    auto end = std::chrono::steady_clock::now();
    std::chrono::duration<double, std::micro> elapsed = end - start;
    std::cout << "Elapsed time: " << elapsed.count() << " microseconds" << std::endl;

    enclave.run();

    // aeseappName = NULL;
    // sm4eappName = NULL;
    eappName = NULL;

    // 设置共享内存结束标志,并释放内存
    // 设置qpb 或者 hpb结束，标志该pb读取数据完毕
    shmpb_offset_data = NULL;
    shmpb_offset_flag = NULL;
    // 设置 Keystone Done
    tempmpshb->ready = 2;

    // 断开连接，由go释放内存
    shmdt(shm);
    shm = NULL;



    if (MULTIDISPATH != NULL) {
        free(MULTIDISPATH);
        MULTIDISPATH = NULL;
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

void get_dispath_get_wrapper(void* buffer) {

  struct edge_call* edge_call = (struct edge_call*)buffer;
  uintptr_t call_args;
  size_t arg_len;
  if (edge_call_args_ptr(edge_call, &call_args, &arg_len) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  if (MULTIDISPATH == NULL) {
    std::cout << "MULTIDISPATH == NULL in get_dispath_get_wrapper. MULTIDISPATH: " << MULTIDISPATH << std::endl;
    return;
  }

  if (edge_call_setup_wrapped_ret(edge_call, (void*)MULTIDISPATH, sizeof(MultiDispath))) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  } else {
    edge_call->return_data.call_status = CALL_STATUS_OK;
  }
  
  return;
}

void dispath_buffer_read_wrapper(void* buffer) {
    struct edge_call* edge_call = (struct edge_call*)buffer;
    uintptr_t call_args;
    size_t arg_len;
    if (edge_call_args_ptr(edge_call, &call_args, &arg_len) != 0) {
        edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
        return;
    }

    // std::cout << "host keystone testing " << std::endl;

    if (shmpb_offset_data == NULL) {
        std::cout << "shmpb_offset_data == NULL in dispath_buffer_read_wrapper. shmpb_offset_data: " << shmpb_offset_data << std::endl;
        return;
    }

    if (shmpb_offset_flag == NULL) {
        std::cout << "shmpb_offset_flag == NULL in dispath_buffer_read_wrapper. shmpb_offset_flag: " << shmpb_offset_flag << std::endl;
        return;
    }

    // std::cout << "shmpb_offset_data = " << shmpb_offset_data << "?= &shmpb_offset_flag[count_POSITION] = " << &shmpb_offset_flag[count_POSITION] << std::endl;
    if (&shmpb_offset_flag[count_POSITION] == shmpb_offset_data) {
      if (edge_call_setup_wrapped_ret(edge_call, NULL, 0)) {
        edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
      } else {
        edge_call->return_data.call_status = CALL_STATUS_OK;
      }
      return;
    }

    // std::cout << "numberKeystone " << MULTIDISPATH->numberKeystone << " while start shmpb_offset_flag[count_POSITION] = " << shmpb_offset_flag[count_POSITION] << std::endl;
    // while (shmpb_offset_flag[count_POSITION]==0) {
    //   ;
    // }
    while (shmpb_offset_flag[count_POSITION]<262144) {
      if(count_POSITION < tempmpshb->read_position) {
        break;
      }
    }
    // while (count_POSITION == tempmpshb->read_position) {
    //   ;
    // }
    // while (shmpb_offset_flag[count_POSITION]<(256*1024)) {
    //   if (&shmpb_offset_flag[count_POSITION] + shmpb_offset_flag[count_POSITION] == shmpb_offset_data)
    //     break;
    // }
    // std::cout << "numberKeystone " << MULTIDISPATH->numberKeystone << " while end  shmpb_offset_flag[count_POSITION] = " << shmpb_offset_flag[count_POSITION] << std::endl;

    if (edge_call_setup_wrapped_ret(edge_call, (void*)((char*)shmpb_offset_data + (count_POSITION << 18)), shmpb_offset_flag[count_POSITION])) {
      edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
    } else {
      edge_call->return_data.call_status = CALL_STATUS_OK;
    }

    count_POSITION++;

}

