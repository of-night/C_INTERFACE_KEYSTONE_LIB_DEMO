#include <edge_call.h>
#include <keystone.h>
#include "ipfs_keystone.h"
#include <iostream>
#include <chrono>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h>

// #define TESTLOG

#define THE_SIZE(TYPE) (sizeof(TYPE))

#define THE_NEW_DIR_DISPATCH_SHMKEY_JUST_CALL (250530)
TheNewDirMultiProcessTEESecureDispatchSHMBufferJustCall* TEMP_TNDMSDSHM_JUST_CALL = NULL;
#define SIZE_TEMP_TNDMSDSHM THE_SIZE(TheNewDirMultiProcessTEESecureDispatchSHMBufferJustCall)
TheNewDirMultiProcessTEESecureDispatchSHMBufferTransferFile* TNDMULTIDISPATCH_TRANSFER_FILE = NULL;
#define SIZE_TNDMULTIDISPATCH THE_SIZE(TheNewDirMultiProcessTEESecureDispatchSHMBufferTransferFile)

TheNewDirSecureMultiDispatch *theNewDieSecureDispatch = NULL;
#define SIZE_TNDDISPATCH THE_SIZE(TheNewDirSecureMultiDispatch)

#define SIZE_INT THE_SIZE(int)
#define SIZE_ULONG THE_SIZE(unsigned long)
#define SIZE_LONGLONG THE_SIZE(long long)

// keystone ready flag
int *KEYSTONE_READY_FLAG = NULL;

// 数据存放的起始位置
// 数组指针
void *transfer_file_shm_offset_data = NULL;
// 数据是否被取走
unsigned int* transfer_file_shm_offset_flag = NULL;
// 读取的位置i
long long count_POSITION = 0;

#define OCALL_PRINT_STRING                        1
#define OCALL_DISPATCH_GET                        5
#define OCALL_DISPATCH_GET_BUFFER_READ            7
#define OCALL_DISPATCH_FILEFLAG_GET_BUFFER_READ   9

unsigned long print_string(char* str);
void print_string_wrapper(void* buffer);
void get_dispatch_get_wrapper(void* buffer);
void dispatch_fileflag_buffer_read_wrapper(void* buffer);
void dispatch_buffer_read_wrapper(void* buffer);

// 初始化设置 TEMP_TNDMSDSHM_JUST_CALL 和 连接shm just call
// set KEYSTONE_READY_FLAG
// set TEMP_TNDMSDSHM_JUST_CALL
int initializeTheNewDieDispatchJustCall(int shmSizeJustCall, int flexible);

// attach shm transfer file
// set transfer_file_shm_offset_flag
// set transfer_file_shm_offset_data
int setTheNewDieDispatchTransferFile(long long fileCount, long long fileSize);

// detach shm transfer file
// free transfer_file_shm_offset_flag
// free transfer_file_shm_offset_data
// free count_POSITION
void freeTheNewDieDispatchTransferFile();

// 初始化设置 TNDMULTIDISPATCH_TRANSFER_FILE 和 attach shm transfer file
int initializeTheNewDieDispatchTransferFile();

#ifdef TESTLOG
FILE *file;
#endif

long long isSlave = 0;

int main(int argc, char *argv[]) {
	if (argc != 6) {
        printf("Usage: %s <is_aes> <shm_size> <start_offset> <flexible> <engine_id>\n", argv[0]);
        return 0;
    }

    int isAES = atoi(argv[1]);
    int shmSizeJustCall = atoi(argv[2]);
    long long start_offset = atoi(argv[3]);
    int flexible = atoi(argv[4]);
    unsigned long long engine_id = atoi(argv[5]);

	start_offset == 0 ? isSlave = 0 : isSlave = 1;

	#ifdef TESTLOG
	char logName[] = "host_a_the_new_dir_log.txt";
	logName[5] += start_offset;
    file = fopen(logName, "wb");
	if (file == NULL) {
		printf("Failed to open file");
		return -1;
	}
	#endif

    theNewDieSecureDispatch = (TheNewDirSecureMultiDispatch*)malloc(SIZE_TNDDISPATCH);
    theNewDieSecureDispatch->start_offset = start_offset;
    theNewDieSecureDispatch->numberKeystone = flexible;

    // 初始化设置 MULTIDISPATCH 和连接 shm
    // set KEYSTONE_READY_FLAG
    // set TEMP_TNDMSDSHM_JUST_CALL
    if (initializeTheNewDieDispatchJustCall(shmSizeJustCall, flexible)) {
      printf("initialize TEMP_TNDMSDSHM_JUST_CALL and attach shm just call error\n");
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

    char aeseappName[] = "thenewdirsecuremultideaes";
    char sm4eappName[] = "thenewdirsecuremultidesm4";

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
        std::cout << "thenewdirsecuredemultiTEE do nothing" << std::endl;
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
	register_call(OCALL_DISPATCH_FILEFLAG_GET_BUFFER_READ, dispatch_fileflag_buffer_read_wrapper);

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
	#ifdef TESTLOG
	fprintf(file, "init time:%lf\n", elapsed.count());
	fflush(file);
	#endif

    enclave.run();

	#ifdef TESTLOG
	fprintf(file, "run done\n");
	fflush(file);
	#endif
    // aeseappName = NULL;
    // sm4eappName = NULL;
    eappName = NULL;

    // 设置共享内存结束标志,并释放内存
    // 设置qpb 或者 hpb结束，标志该pb读取数据完毕
    transfer_file_shm_offset_data = NULL;
    transfer_file_shm_offset_flag = NULL;
    // 设置 Keystone Done
    if (start_offset == 0) {
      for (int i = flexible - 1; i > 0;i--) {
        while(*(KEYSTONE_READY_FLAG + i) != 2){

        }
      }
    }
    *(KEYSTONE_READY_FLAG + start_offset) = 2;

    // 断开连接，由go释放内存
    shmdt((void*)KEYSTONE_READY_FLAG);
    KEYSTONE_READY_FLAG = NULL;



    if (theNewDieSecureDispatch != NULL) {
        free(theNewDieSecureDispatch);
        theNewDieSecureDispatch = NULL;
    }

    std::cout << start_offset << " enclave done" << std::endl;

	#ifdef TESTLOG
	fclose(file);
	#endif
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
  memcpy((void*)data_section, &ret_val, SIZE_ULONG);
  if (edge_call_setup_ret(
          edge_call, (void*)data_section, SIZE_ULONG)) {
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

  if (theNewDieSecureDispatch == NULL) {
    std::cout << "theNewDieSecureDispatch == NULL in get_dispatch_get_wrapper. theNewDieSecureDispatch: " << theNewDieSecureDispatch << std::endl;
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
    return;
  }

  if (edge_call_setup_wrapped_ret(edge_call, (void*)theNewDieSecureDispatch, SIZE_TNDDISPATCH)) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  } else {
    edge_call->return_data.call_status = CALL_STATUS_OK;
  }
  
  return;
}

void dispatch_buffer_read_wrapper(void* buffer) {
	#ifdef TESTLOG
	fprintf(file, "func:%s start\n", __func__);
	fflush(file);
	#endif
    struct edge_call* edge_call = (struct edge_call*)buffer;
    uintptr_t call_args;
    size_t arg_len;
    if (edge_call_args_ptr(edge_call, &call_args, &arg_len) != 0) {
        edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
        return;
    }

    // std::cout << "host keystone testing " << std::endl;

    if (TNDMULTIDISPATCH_TRANSFER_FILE == NULL || transfer_file_shm_offset_data == NULL || transfer_file_shm_offset_flag == NULL) {
		#ifdef TESTLOG
		fprintf(file, "func:%s erro!!!! dispatch_buffer_read_wrapper.\n", __func__);
		#endif
      std::cout << "erro!!!! dispatch_buffer_read_wrapper." << std::endl;
      return;
    }

    // std::cout << "transfer_file_shm_offset_data = " << transfer_file_shm_offset_data << "?= &transfer_file_shm_offset_flag[count_POSITION] = " << &transfer_file_shm_offset_flag[count_POSITION] << std::endl;
    if (&transfer_file_shm_offset_flag[count_POSITION] == transfer_file_shm_offset_data) {
      freeTheNewDieDispatchTransferFile();
      if (edge_call_setup_wrapped_ret(edge_call, NULL, 0)) {
        edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
      } else {
        edge_call->return_data.call_status = CALL_STATUS_OK;
		#ifdef TESTLOG
		fprintf(file, "func:%s done\n", __func__);
		fflush(file);
		#endif
      }
      return;
    }

    while (transfer_file_shm_offset_flag[count_POSITION]<262144) {
		#ifdef TESTLOG
		fprintf(file, "func:%s wait get, size:%d\n", __func__, transfer_file_shm_offset_flag[count_POSITION]);
		fflush(file);
		#endif
      if(count_POSITION < TNDMULTIDISPATCH_TRANSFER_FILE->read_position) {
        break;
      }
    }
	#ifdef TESTLOG
	fprintf(file, "func:%s get end, size:%d\n", __func__, transfer_file_shm_offset_flag[count_POSITION]);
	fflush(file);
	#endif

    if (edge_call_setup_wrapped_ret(edge_call, (void*)((char*)transfer_file_shm_offset_data + (count_POSITION<<18)), transfer_file_shm_offset_flag[count_POSITION])) {
      edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
    } else {
      edge_call->return_data.call_status = CALL_STATUS_OK;
    }

    count_POSITION++;
}

void dispatch_fileflag_buffer_read_wrapper(void* buffer) {
	#ifdef TESTLOG
	fprintf(file, "func:%s start\n", __func__);
	fflush(file);
	#endif
    struct edge_call* edge_call = (struct edge_call*)buffer;
    uintptr_t call_args;
    size_t arg_len;
    if (edge_call_args_ptr(edge_call, &call_args, &arg_len) != 0) {
        edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
        return;
    }

    // std::cout << "host keystone testing " << std::endl;

    if (TNDMULTIDISPATCH_TRANSFER_FILE != NULL || transfer_file_shm_offset_data != NULL || transfer_file_shm_offset_flag != NULL || count_POSITION != 0) {
      std::cout << "erro!!!! dispatch_fileflag_buffer_read_wrapper." << std::endl;
      return;
    }

    long long tempFlag;
    while(1) {
      	tempFlag = TEMP_TNDMSDSHM_JUST_CALL->shmReady;
      	if (tempFlag == 4) {
      	  	if (edge_call_setup_wrapped_ret(edge_call, NULL, 0)) {
      	  	  	edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
      	  	} else {
      	  	  	edge_call->return_data.call_status = CALL_STATUS_OK;
				#ifdef TESTLOG
				fprintf(file, "func:%s end 4\n", __func__);
				fflush(file);
				#endif
      	  	}
      	  	return;
      	}

      	if (tempFlag == 1) {
			// 如果是从enclave则继续循环
			// 等待main enclave将shmReady置为2
			// 标志开始读取数据
			if (isSlave) {
				continue;
			}
      	  	if (!initializeTheNewDieDispatchTransferFile() && edge_call_setup_wrapped_ret(edge_call, &tempFlag, SIZE_LONGLONG)) {
      	  		edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
      	  	} else {
      	  		edge_call->return_data.call_status = CALL_STATUS_OK;
				#ifdef TESTLOG
				fprintf(file, "func:%s end 1\n", __func__);
				fflush(file);
				#endif
      	  	}
      	  	return;
      	}

		  if (tempFlag == 2) {
			// 如果是主enclave则继续循环
			// 一般情况下主enclave不会到这里
			// 除非出现错误
			if (!isSlave) {
				#ifdef TESTLOG
				fprintf(file, "func:%s end 2\n", __func__);
				fflush(file);
				#endif
				continue;
			}
      	  	if (edge_call_setup_wrapped_ret(edge_call, &tempFlag, SIZE_LONGLONG)) {
      	  		edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
      	  	} else {
      	  		edge_call->return_data.call_status = CALL_STATUS_OK;
				#ifdef TESTLOG
				fprintf(file, "func:%s end 1\n", __func__);
				fflush(file);
				#endif
      	  	}
      	  	return;
      	}
		
    }
}

// 初始化设置 TEMP_TNDMSDSHM_JUST_CALL 和 连接shm just call
int initializeTheNewDieDispatchJustCall(int shmSizeJustCall, int flexible) {

  // 创建共享内存，并设置共享内存开始结构
  // 创建共享内存
  int shmid = shmget(THE_NEW_DIR_DISPATCH_SHMKEY_JUST_CALL, shmSizeJustCall, 0666);
  if (shmid == -1) {
    perror("Failed to get shared memory just call");
    return 1;
  }

  char *temp_shmaddr_just_call;
  temp_shmaddr_just_call = (char*)shmat(shmid, NULL, 0);
  if (temp_shmaddr_just_call == (char *)-1) {
    perror("Failed to attach shared memory just call");
    return 1;
  }

  // 设置共享内存结构,并初始化
  // self keystone ready flag
  // just call
  KEYSTONE_READY_FLAG = ((int*)temp_shmaddr_just_call);
  int keystone_ready_flag_size = SIZE_INT * flexible;
  TEMP_TNDMSDSHM_JUST_CALL = (TheNewDirMultiProcessTEESecureDispatchSHMBufferJustCall*)(temp_shmaddr_just_call + keystone_ready_flag_size);

  return 0;

}

// detach shm transfer file
// free transfer_file_shm_offset_flag
// free transfer_file_shm_offset_data
// free count_POSITION
void freeTheNewDieDispatchTransferFile() {
  
  transfer_file_shm_offset_flag = NULL;
  transfer_file_shm_offset_data = NULL;
  count_POSITION = 0;

  shmdt((void*)TNDMULTIDISPATCH_TRANSFER_FILE);
  TNDMULTIDISPATCH_TRANSFER_FILE = NULL;

  TEMP_TNDMSDSHM_JUST_CALL->shmReady = 3;
}

// attach shm transfer file
// set transfer_file_shm_offset_flag
// set transfer_file_shm_offset_data
// set count_POSITION
int setTheNewDieDispatchTransferFile(long long fileCount, long long fileSize) {
  // 创建共享内存，并设置共享内存开始结构
  // 创建共享内存
  int shmid = shmget(THE_NEW_DIR_DISPATCH_SHMKEY_JUST_CALL + fileCount, fileSize, 0666);
  if (shmid == -1) {
    perror("Failed to get shared memory transfer file");
    return 1;
  }

  char *temp_shmaddr_transfer_file;
  temp_shmaddr_transfer_file = (char*)shmat(shmid, NULL, 0);
  if (temp_shmaddr_transfer_file == (char *)-1) {
    perror("Failed to attach shared memory transfer file");
    return 1;
  }

  if (TNDMULTIDISPATCH_TRANSFER_FILE == NULL && transfer_file_shm_offset_flag == NULL && transfer_file_shm_offset_data == NULL && count_POSITION == 0) {
    TNDMULTIDISPATCH_TRANSFER_FILE = (TheNewDirMultiProcessTEESecureDispatchSHMBufferTransferFile*)temp_shmaddr_transfer_file;
    transfer_file_shm_offset_flag = (unsigned int *)(temp_shmaddr_transfer_file + SIZE_TNDMULTIDISPATCH);
    transfer_file_shm_offset_data = (void*)(temp_shmaddr_transfer_file + TNDMULTIDISPATCH_TRANSFER_FILE->dataptr_offset);
    count_POSITION = 0;
    return 0;
  }

  return 1;
}

// 初始化设置 TNDMULTIDISPATCH_TRANSFER_FILE 和 attach shm transfer file
int initializeTheNewDieDispatchTransferFile() {
  if (TEMP_TNDMSDSHM_JUST_CALL==NULL) {
    printf("TEMP_TNDMSDSHM_JUST_CALL == NULL error\n");
    return 1;
  }

  while(1) {
    if (TEMP_TNDMSDSHM_JUST_CALL->shmReady == 1) {
      if (setTheNewDieDispatchTransferFile(TEMP_TNDMSDSHM_JUST_CALL->fileCount, TEMP_TNDMSDSHM_JUST_CALL->fileSize) == 0) {
        TEMP_TNDMSDSHM_JUST_CALL->shmReady = 2;
        break;
      }
      return 1;
    }
  }

  return 0;
}
