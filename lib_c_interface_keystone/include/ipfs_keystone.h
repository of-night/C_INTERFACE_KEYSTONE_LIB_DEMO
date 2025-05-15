#ifndef IPFS_KEYSTONE_H
#define IPFS_KEYSTONE_H

#define AES 1
#define SM4 2
#define demo 3

#ifdef __cplusplus
extern "C" {
#endif

// #define BUFFER_SIZE 256 * 1024 * 15 + 1  // 768KB + 1 KB + 3MB
#define BUFFER_SIZE (256 * 1024 * 3 + 1)  // 768KB + 1 KB
#define CHUNK_SIZE (256 * 1024)   // 256 KB

typedef struct {
    char buffer[BUFFER_SIZE];       // 缓冲区存储数据
    int read_pos;                   // 当前读位置
    int write_pos;                  // 当前写位置
    volatile int running;           // 标记是否正在运行
} RingBuffer;

// 初始化环形缓冲区
void init_ring_buffer(RingBuffer *rb);

// 获取缓冲区可用空间大小
int ring_buffer_space_available(RingBuffer *rb);

// 获取缓冲区已使用空间大小
int ring_buffer_space_used(RingBuffer *rb);

// 从缓冲区读取数据
int ring_buffer_read(RingBuffer *rb, char *data, int length, int *readLen);

// 向缓冲区写入数据
int ring_buffer_write(RingBuffer *rb, const char *data, size_t length);

void ipfs_keystone(int isAES, void *fileName, void* rb);

void ipfs_keystone_de(int isAES, void *fileName, void* rb);

// 设置ring_buffer的运行状态为停止
void ring_buffer_stop(RingBuffer *rb);

// 判断释放ring_buffer释放的时机
void ring_buffer_already_got();


// ==================================================================================
//							MultiTheaded Keystone Aes encrypt
// ==================================================================================

// 半部分缓冲区
typedef struct {
    volatile int read_pos;          // 当前读位置
    volatile int write_pos;         // 当前写位置
    volatile int running;           // 标记是否正在运行
    volatile int MaxSpace;          // 标记是否正在运行
    char *buffer;
} HalfPartBuffer;

typedef struct {
    HalfPartBuffer ppb;             // 前半部分
    HalfPartBuffer hpb;             // 后半部分
} MultiThreadedBuffer;

typedef struct {
    char fileName[20];
    int offset;
    int maxspace;
} MultiFile;

// 初始化半部分缓冲区
void init_half_part_buffer(HalfPartBuffer *pb, int buffersize);

// 释放半部分缓冲区
void destory_half_part_buffer(HalfPartBuffer *pb);

// 初始化多线程缓冲区
void init_multi_threaded_ring_buffer(MultiThreadedBuffer *mtb, int fileSize, int sizeppb);

// 释放多线程缓冲区
void destory_multi_threaded_ring_buffer(MultiThreadedBuffer *mtb);

// 使用前半部分缓冲区KEYSTONE
void multi_ipfs_keystone_ppb_buffer(int isAES, void* fileName, void* pb, int offset, int maxspace);

// 使用后半部分缓冲区KEYSTONE
void multi_ipfs_keystone_hpb_buffer(int isAES, void* fileName, void* pb, int offset, int maxspace);

// 封装使用前半部分缓冲区KEYSTONE
void multi_ipfs_keystone_ppb_buffer_wrapper(int isAES, void* fileName, void* mtb, int offset, int maxspace);

// 封装使用后半部分缓冲区KEYSTONE
void multi_ipfs_keystone_hpb_buffer_wrapper(int isAES, void* fileName, void* mtb, int offset, int maxspace);

int alignedFileSize(int fileSize);

int aFileSize(int fileSize);

// ipfs从buffer中读取数据
int which_pb_buffer_read(MultiThreadedBuffer *mtb, char *data, int length, int *readLen);


// ==================================================================================
//				Multi-process Keystone Encrypt
// ==================================================================================

// 半部分缓冲区
typedef struct {
    int read_pos;          // 当前读位置
    int write_pos;         // 当前写位置
    int running;           // 标记是否正在运行
    int MaxSpace;          // 标记是否正在运行
} HalfPartSHMBuffer;

typedef struct {
    HalfPartSHMBuffer qpb;             // 前半部分
    HalfPartSHMBuffer hpb;             // 后半部分
    int offset;
} MultiProcessSHMBuffer;


#define shmKey (241227)

// 创建共享内存
void *creat_shareMemory(int shmsize);

// 为当前进程连接共享内存
void *attach_shareMemory(int shmsize);

// 断开连接共享内存
void detach_shareMemory(void* shmaddr);

// 删除共享内存段
void removeShm(int shmsize);



int MultiProcessRead(void* shmaddr, int shmsize, void* data, int len, int* readLen);

void waitKeystoneReady(void *shmaddr);


// ==================================================================================
//				Multi-process Cross-read Keystone Encrypt
// ==================================================================================
typedef struct {
    int ready1;             
    int ready2;             
    long long read_position;             
    long long offset;
} MultiProcessCrossSHMBuffer;

typedef struct {
    char fileName[50];
    long long start_offset;
} MultiCrossFile;

// 16字节对齐
long long long_alignedFileSize(long long fileSize);

// 计算块的数量，向上取整
long long long_alignedFileSize_blocksnums(long long fileSize);

// 创建共享内存
void *long_create_shareMemory(long long shmsize);

// 删除共享内存段
void long_removeShm(long long shmsize);

// 启动keystone之前先初始化内存空间
void crossInitSHM(void *shmaddr, long long blocksNums);

// 等待keystone already
void crosswaitKeystoneReady(void *shmaddr);

// ipfs 读数据
int MultiProcessCrossRead(void* shmaddr, int shmsize, void* data, int len, int* readLen);


// ==================================================================================
//				Multi-process Cross-read Flexible Keystone Encrypt
// ==================================================================================

#define MAXKEYSTONENUMBER 10

typedef struct {
    int ready[MAXKEYSTONENUMBER];                          
    long long read_position;             
    long long offset;
} MultiProcessCrossFlexibleSHMBuffer;

typedef struct {
    char fileName[50];
    long long start_offset;
    int numberKeystone;
} MultiCrossFlexibleFile;

// MAXNUM 10
void fixFlexibleNum(void* flexible);

// 启动keystone之前先初始化内存空间
void flexiblecrossInitSHM(void *shmaddr, long long blocksNums);

// 等待keystone already
void flexiblecrosswaitKeystoneReady(void *shmaddr, int flexible);

// ipfs 读数据
int MultiProcessCrossReadFlexible(void* shmaddr, int shmsize, void* data, int len, int* readLen);


// ==================================================================================
//				Multi-process Keystone Decrypt
// ==================================================================================

typedef struct {
    int ready;                          
    long long read_position;             
    long long offset;
} MultiProcessTEEDispatchSHMBuffer;

typedef struct {
    long long start_offset;
    int numberKeystone;
} MultiDispath;

#define dispath_shmKey 250227

// 设置总大小
void dispathSetLength(unsigned long long size);

// 获取总大小
void dispathGetLength(unsigned long long *size);

// 计算每个enclave最少dispath的blocks数量，和剩余的数量
void dispath_blocks(unsigned long long fileSize, void* eblock, void* seblock, int flexible);

// 创建共享内存
void *dispath_long_create_shareMemory(long long shmsize, int en_id);

// 断开连接共享内存
void dispath_detach_shareMemory(void* shmaddr);

// 删除共享内存段
void dispath_long_removeShm(long long shmsize, int en_id);

// 启动keystone之前先初始化内存空间
void dispath_InitSHM(void *shmaddr, long long blocksNums);

// 等待keystone already
int dispathwaitKeystoneReady(void *shmaddr);

// 计算bnumber
long long dispathBNumber(long long* blockcount, int flexible);

// 调度器将数据读取到调度器与enclave之间的共享内存中
int dispath_data_block(void *shmaddr, long long shmsize, char* p, int pLen, int* readLen);

// 调度器将数据读取到调度器与enclave之间的共享内存中
int dispath_data_block_4096(void *shmaddr, long long shmsize, char* p, int pLen, int* readLen);

unsigned long long getDispathEngineSeq();

// ==================================================================================
//				Multi-process Keystone Decrypt secure dispatch
// ==================================================================================

#define SECURE_DISPATCH_SHMKEY (250509)

typedef struct {
    long long start_offset;     // 是第几个enclave，如果是0，则是main，其余则是slave
    int numberKeystone;         // 一共有几个enclave
} SecureMultiDispatch;

typedef struct {                        
    long long read_position;             
    long long offset;
} MultiProcessTEESecureDispatchSHMBuffer;

// create shm
void* secure_dispatch_ulnoglong_create_shareMemory(unsigned long long shmsize);

// init shm
void secure_dispacth_initSHM(void* shmaddr, unsigned long long blockNum, int flexible);

// get shmsize
unsigned long long MultiProcessTEESecureDispatchGetSHMSize(unsigned long long fileSize, void* blockNum, int flexible);

// detach shm
void secure_dispatch_detach_shareMemory(void* shmaddr);

// remove shm
void secure_dispatch_ulnoglong_remove_shareMemory(unsigned long long shmsize);

// 等待keystone already
void secure_dispatch_waitKeystoneReady(void *shmaddr, int flexible);

// 等待keystone done
void secure_dispatch_waitKeystoneDone(void *shmaddr, int flexible);

int secure_dispatch_write(void *shmaddr, long long shmsize, char* p, int pLen, int* readLen, int flexible);

#ifdef __cplusplus
}
#endif

#endif //IPFS_KEYSTONE_H


