#ifndef IPFS_KEYSTONE_H
#define IPFS_KEYSTONE_H

#define AES 1
#define SM4 2
#define demo 3

#ifdef __cplusplus
extern "C" {
#endif

// #define BUFFER_SIZE 256 * 1024 * 15 + 1  // 768KB + 1 KB + 3MB
#define BUFFER_SIZE 256 * 1024 * 3 + 1  // 768KB + 1 KB
#define CHUNK_SIZE 256 * 1024   // 256 KB

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

#ifdef __cplusplus
}
#endif

#endif //IPFS_KEYSTONE_H

