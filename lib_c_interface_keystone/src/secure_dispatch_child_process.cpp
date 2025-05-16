#include <edge_call.h>
#include <keystone.h>
#include "ipfs_keystone.h"
#include <iostream>
#include <chrono>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h>

#define DISPATCH_SHMKEY 250509
int SHMSIZE = 0;
char *SHMADDR = NULL;
MultiProcessTEESecureDispatchSHMBuffer* TEMP_MSDSHM = NULL;
#define SIZE_TEMP_MSDSHM sizeof(MultiProcessTEESecureDispatchSHMBuffer)

// keystone ready flag
int *KEYSTONE_READY_FLAG = NULL;

// 数据存放的起始位置
void* shm_offset_data = NULL;
// 数据是否被取走
unsigned int* shm_offset_flag = NULL;
// 读取的位置i
long long count_POSITION = 0;

#define OCALL_PRINT_STRING              1
#define OCALL_DISPATCH_GET              5
#define OCALL_DISPATCH_GET_BUFFER_READ  7

unsigned long print_string(char* str);
void print_string_wrapper(void* buffer);
void get_dispatch_get_wrapper(void* buffer);
void dispatch_buffer_read_wrapper(void* buffer);

SecureMultiDispatch* MULTIDISPATCH = NULL;

// 初始化设置 MULTIDISPATCH 和 连接shm
int initializeDispatch(long long start_offset, int flexible);

// 初始化设置 MULTIDISPATCH
int setMultiDispatch(long long start_offset, int flexible);

int main(int argc, char *argv[]) {
    if (argc != 6) {
        printf("Usage: %s <is_aes> <shm_size> <start_offset> <flexible> <engine_id>\n", argv[0]);
        return 0;
    }

    int isAES = atoi(argv[1]);
    SHMSIZE = atoi(argv[2]);
    long long start_offset = atoi(argv[3]);
    int flexible = atoi(argv[4]);
    unsigned long long engine_id = atoi(argv[5]);

    // 初始化设置 MULTIDISPATCH 和连接 shm
    if (initializeDispatch(start_offset, flexible)) {
      printf("initialize MULTIDISPATCH and attach shm error\n");
      return -1;
    }
 
    // 获取当前时间点
    auto start = std::chrono::steady_clock::now();

    Keystone::Enclave enclave;
    Keystone::Params params;

    params.setFreeMemSize(256 * 1024 * 1024);
    params.setUntrustedSize(2 * 1024 * 1024);
    // params.setYXms(1);
    params.setEngineID(engine_id);
    params.setYXms(flexible);
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

    char aeseappName[] = "securemultideaes";
    char sm4eappName[] = "securemultidesm4";

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
        std::cout << "securedemultiTEE do nothing" << std::endl;
        return 0;
    }

    std::cout << "host init end" << std::endl;

    enclave.registerOcallDispatch(incoming_call_dispatch);

    /* We must specifically register functions we want to export to the
       enclave. */
    register_call(OCALL_PRINT_STRING, print_string_wrapper);
    register_call(OCALL_DISPATCH_GET, get_dispatch_get_wrapper);
    // just main register this call
    if (start_offset == 0) {
      register_call(OCALL_DISPATCH_GET_BUFFER_READ, dispatch_buffer_read_wrapper);
    }

    edge_call_init_internals(
        (uintptr_t)enclave.getSharedBuffer(), enclave.getSharedBufferSize());

    // 设置 Keystone already
    // wati main enclave ready
    if (KEYSTONE_READY_FLAG == NULL) {
      std::cout << "KEYSTONE_READY_FLAG == NULL, error" << std::endl;
      return 0;
    }
    while(start_offset) {
      if (*KEYSTONE_READY_FLAG == 1) {
        break;
      }
    }
    *(KEYSTONE_READY_FLAG + start_offset) = 1;

    auto end = std::chrono::steady_clock::now();
    std::chrono::duration<double, std::micro> elapsed = end - start;
    std::cout << "Elapsed time: " << elapsed.count() << " microseconds" << std::endl;

    enclave.run();

    // aeseappName = NULL;
    // sm4eappName = NULL;
    eappName = NULL;

    // 设置共享内存结束标志,并释放内存
    // 设置qpb 或者 hpb结束，标志该pb读取数据完毕
    shm_offset_data = NULL;
    shm_offset_flag = NULL;
    // 设置 Keystone Done
    if (start_offset == 0) {
      for (int i = flexible - 1; i > 0;i--) {
        while(*(KEYSTONE_READY_FLAG + i) == 2){

        }
      }
    }
    *(KEYSTONE_READY_FLAG + start_offset) = 2;

    // 断开连接，由go释放内存
    shmdt(SHMADDR);
    SHMADDR = NULL;



    if (MULTIDISPATCH != NULL) {
        free(MULTIDISPATCH);
        MULTIDISPATCH = NULL;
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

void get_dispatch_get_wrapper(void* buffer) {

  struct edge_call* edge_call = (struct edge_call*)buffer;
  uintptr_t call_args;
  size_t arg_len;
  if (edge_call_args_ptr(edge_call, &call_args, &arg_len) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  if (MULTIDISPATCH == NULL) {
    std::cout << "MULTIDISPATCH == NULL in get_dispatch_get_wrapper. MULTIDISPATCH: " << MULTIDISPATCH << std::endl;
    return;
  }

  if (edge_call_setup_wrapped_ret(edge_call, (void*)MULTIDISPATCH, sizeof(SecureMultiDispatch))) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  } else {
    edge_call->return_data.call_status = CALL_STATUS_OK;
  }
  
  return;
}

void dispatch_buffer_read_wrapper(void* buffer) {
    struct edge_call* edge_call = (struct edge_call*)buffer;
    uintptr_t call_args;
    size_t arg_len;
    if (edge_call_args_ptr(edge_call, &call_args, &arg_len) != 0) {
        edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
        return;
    }

    // std::cout << "host keystone testing " << std::endl;

    if (shm_offset_data == NULL) {
        std::cout << "shm_offset_data == NULL in dispatch_buffer_read_wrapper. shm_offset_data: " << shm_offset_data << std::endl;
        return;
    }

    if (shm_offset_flag == NULL) {
        std::cout << "shm_offset_flag == NULL in dispatch_buffer_read_wrapper. shm_offset_flag: " << shm_offset_flag << std::endl;
        return;
    }

    // std::cout << "shm_offset_data = " << shm_offset_data << "?= &shm_offset_flag[count_POSITION] = " << &shm_offset_flag[count_POSITION] << std::endl;
    if (&shm_offset_flag[count_POSITION] ==   ) {
      if (edge_call_setup_wrapped_ret(edge_call, NULL, 0)) {
        edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
      } else {
        edge_call->return_data.call_status = CALL_STATUS_OK;
      }
      return;
    }

    // std::cout << "numberKeystone " << MULTIDISPATCH->numberKeystone << " while start shm_offset_flag[count_POSITION] = " << shm_offset_flag[count_POSITION] << std::endl;
    // while (shm_offset_flag[count_POSITION]==0) {
    //   ;
    // }
    while (shm_offset_flag[count_POSITION]<262144) {
      if(count_POSITION < TEMP_MSDSHM->read_position) {
        break;
      }
    }
    // while (count_POSITION == TEMP_MSDSHM->read_position) {
    //   ;
    // }
    // while (shm_offset_flag[count_POSITION]<(256*1024)) {
    //   if (&shm_offset_flag[count_POSITION] + shm_offset_flag[count_POSITION] == shm_offset_data)
    //     break;
    // }
    // std::cout << "numberKeystone " << MULTIDISPATCH->numberKeystone << " while end  shm_offset_flag[count_POSITION] = " << shm_offset_flag[count_POSITION] << std::endl;

    if (edge_call_setup_wrapped_ret(edge_call, (void*)((char*)shm_offset_data + (count_POSITION << 18)), shm_offset_flag[count_POSITION])) {
      edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
    } else {
      edge_call->return_data.call_status = CALL_STATUS_OK;
    }

    count_POSITION++;

}

// 初始化设置 MULTIDISPATCH
int setMultiDispatch(long long start_offset, int flexible) {
  MULTIDISPATCH = (SecureMultiDispatch*)malloc(sizeof(SecureMultiDispatch));
  if (MULTIDISPATCH == NULL) {
    printf("malloc MULTIDISPATCH memory error\n");
    return 1;
  }

  MULTIDISPATCH->start_offset = start_offset;  
  MULTIDISPATCH->numberKeystone = flexible;

  return 0;
}

// 初始化设置 MULTIDISPATCH 和 连接shm
int initializeDispatch(long long start_offset, int flexible) {
  if (setMultiDispatch(start_offset, flexible)) {
    printf("set MULTIDISPATCH error\n");
    return 1;
  }

  // 创建共享内存，并设置共享内存开始结构
  // 创建共享内存
  int shmid = shmget(DISPATCH_SHMKEY, SHMSIZE, 0666);
  if (shmid == -1) {
    perror("Failed to get shared memory");
    return 1;
  }

  SHMADDR = (char*)shmat(shmid, NULL, 0);
  if (SHMADDR == (char *)-1) {
    perror("Failed to attach shared memory");
    return 1;
  }

  // 设置共享内存结构,并初始化
  // self keystone ready flag
  KEYSTONE_READY_FLAG = ((int*)SHMADDR);
  int keystone_ready_flag_size = sizeof(int) * flexible;
  TEMP_MSDSHM = (MultiProcessTEESecureDispatchSHMBuffer*)(SHMADDR + keystone_ready_flag_size);

  shm_offset_flag = (unsigned int*)(SHMADDR + keystone_ready_flag_size + SIZE_TEMP_MSDSHM);
  shm_offset_data = (void*)(SHMADDR + TEMP_MSDSHM->offset);
  count_POSITION = 0;

  return 0;

}
