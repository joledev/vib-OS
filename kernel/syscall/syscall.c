/*
 * UnixOS Kernel - System Call Implementation
 */

#include "syscall/syscall.h"
#include "apps/kapi.h"
#include "arch/arch.h"
#include "drivers/uart.h"
#include "fs/vfs.h"
#include "mm/kmalloc.h"
#include "printk.h"
#include "sched/sched.h"

/* ===================================================================== */
/* File Descriptor Table */
/* ===================================================================== */

static struct files_struct *current_files(void) {
  struct task_struct *current = get_current();
  if (!current) {
    return NULL;
  }
  if (!current->files && task_init_files(current) < 0) {
    return NULL;
  }
  return current->files;
}

static struct mm_struct *current_mm(void) {
  struct task_struct *current = get_current();
  return current ? current->mm : NULL;
}

static int alloc_fd(void) {
  struct files_struct *files = current_files();
  if (!files) {
    return -1;
  }
  for (int i = 3; i < TASK_MAX_FDS; i++) {
    if (!files->fd[i].in_use) {
      files->fd[i].in_use = 1;
      return i;
    }
  }
  return -1;
}

static void free_fd(int fd) {
  struct files_struct *files = current_files();
  if (files && fd >= 0 && fd < TASK_MAX_FDS) {
    files->fd[fd].file = NULL;
    files->fd[fd].flags = 0;
    files->fd[fd].in_use = 0;
  }
}

static struct file *get_file(int fd) {
  struct files_struct *files = current_files();
  if (!files || fd < 0 || fd >= TASK_MAX_FDS || !files->fd[fd].in_use) {
    return NULL;
  }
  return files->fd[fd].file;
}

/* ===================================================================== */
/* User Pointer Validation */
/* ===================================================================== */

/* Valid memory regions for user processes */
#define KERNEL_START 0x40000000UL
#define KERNEL_END 0x50000000UL

/* Check if pointer is in valid user-accessible memory range */
static int is_valid_user_ptr(uint64_t ptr, size_t len) {
  if (ptr == 0)
    return 0;

  /* Prevent overflow */
  if (len > 0 && ptr > UINT64_MAX - len)
    return 0;
  uint64_t end = ptr + len;

  if (ptr >= 0x10000000UL && end <= 0x14000000UL) {
    struct task_struct *current = get_current();
    if (current && current->mm) {
      uint64_t pos = ptr;
      while (pos < end) {
        struct vm_area *vma = vmm_find_vma(current->mm, pos);
        if (!vma) {
          return 0;
        }
        pos = vma->end < end ? vma->end : end;
      }
      return 1;
    }
    return 0;
  }

  /* Allow legacy process load region. */
  if (ptr >= 0x50000000UL && end < 0x78000000UL) {
    return 1;
  }

  /* Block access to kernel memory */
  if (ptr >= KERNEL_START && ptr < KERNEL_END)
    return 0;

  /* Allow other reasonable addresses (stack, etc.) */
  return 1;
}

/* ===================================================================== */
/* System call table */
/* ===================================================================== */

typedef long (*syscall_fn_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                             uint64_t);

static syscall_fn_t syscall_table[NR_syscalls];

/* ===================================================================== */
/* System call implementations */
/* ===================================================================== */

static long sys_read(uint64_t fd, uint64_t buf, uint64_t count, uint64_t a3,
                     uint64_t a4, uint64_t a5) {
  (void)a3;
  (void)a4;
  (void)a5;

  /* Validate user buffer */
  if (!is_valid_user_ptr(buf, count)) {
    return -EFAULT;
  }

  /* Handle stdin specially */
  if (fd == 0) {
    kapi_t *api = kapi_get();
    char *p = (char *)buf;
    size_t n = 0;

    /* Block until we get at least one character */
    while (n < count) {
      /* Poll for input */
      int c = api->getc();

      if (c >= 0) {
        /* Got a character */
        p[n++] = (char)c;

        /* Return immediately on newline for line-buffering behavior */
        if (c == '\n' || c == '\r') {
          /* Normalize \r to \n */
          if (c == '\r')
            p[n - 1] = '\n';
          return n;
        }
      } else {
        /* No input available */
        if (n > 0) {
          /* We already read something, return it */
          return n;
        }

        /* Nothing read yet, yield and wait */
        extern void process_yield(void);
        process_yield();
      }
    }
    return n;
  }

  struct file *f = get_file((int)fd);
  if (!f) {
    return -EBADF;
  }

  return vfs_read(f, (char *)buf, count);
}

static long sys_write(uint64_t fd, uint64_t buf, uint64_t count, uint64_t a3,
                      uint64_t a4, uint64_t a5) {
  (void)a3;
  (void)a4;
  (void)a5;

  /* Special case: stdout/stderr (fd 1 and 2) go to console */
  if (fd == 1 || fd == 2) {
    const char *str = (const char *)buf;
    for (size_t i = 0; i < count; i++) {
      uart_putc(str[i]);
    }
    return count;
  }

  struct file *f = get_file((int)fd);
  if (!f) {
    return -EBADF;
  }

  return vfs_write(f, (const char *)buf, count);
}

static long sys_openat(uint64_t dirfd, uint64_t pathname, uint64_t flags,
                       uint64_t mode, uint64_t a4, uint64_t a5) {
  (void)a4;
  (void)a5;
  (void)dirfd; /* dirfd ignored - always use absolute paths */

  const char *path = (const char *)pathname;

  /* Allocate file descriptor */
  int fd = alloc_fd();
  if (fd < 0) {
    return -EMFILE; /* Too many open files */
  }

  /* Open the file */
  struct file *f = vfs_open(path, (int)flags, (mode_t)mode);
  if (!f) {
    free_fd(fd);
    return -ENOENT;
  }

  struct files_struct *files = current_files();
  if (!files) {
    vfs_close(f);
    free_fd(fd);
    return -EMFILE;
  }

  files->fd[fd].file = f;
  files->fd[fd].flags = (int)flags;

  return fd;
}

static long sys_close(uint64_t fd, uint64_t a1, uint64_t a2, uint64_t a3,
                      uint64_t a4, uint64_t a5) {
  (void)a1;
  (void)a2;
  (void)a3;
  (void)a4;
  (void)a5;

  /* Don't close stdin/stdout/stderr */
  if (fd < 3) {
    return 0;
  }

  struct file *f = get_file((int)fd);
  if (!f) {
    return -EBADF;
  }

  vfs_close(f);
  free_fd((int)fd);

  return 0;
}

static long sys_lseek(uint64_t fd, uint64_t offset, uint64_t whence,
                      uint64_t a3, uint64_t a4, uint64_t a5) {
  (void)a3;
  (void)a4;
  (void)a5;

  struct file *f = get_file((int)fd);
  if (!f) {
    return -EBADF;
  }

  return vfs_lseek(f, (loff_t)offset, (int)whence);
}

static long sys_exit(uint64_t error_code, uint64_t a1, uint64_t a2, uint64_t a3,
                     uint64_t a4, uint64_t a5) {
  (void)a1;
  (void)a2;
  (void)a3;
  (void)a4;
  (void)a5;

  printk(KERN_INFO "sys_exit: code=%llu\n", (unsigned long long)error_code);
  exit_task((int)error_code);

  /* Never reached */
  return 0;
}

static long sys_exit_group(uint64_t error_code, uint64_t a1, uint64_t a2,
                           uint64_t a3, uint64_t a4, uint64_t a5) {
  return sys_exit(error_code, a1, a2, a3, a4, a5);
}

static long sys_getpid(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                       uint64_t a4, uint64_t a5) {
  (void)a0;
  (void)a1;
  (void)a2;
  (void)a3;
  (void)a4;
  (void)a5;

  struct task_struct *current = get_current();
  return current ? current->pid : -1;
}

static long sys_getppid(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                        uint64_t a4, uint64_t a5) {
  (void)a0;
  (void)a1;
  (void)a2;
  (void)a3;
  (void)a4;
  (void)a5;

  struct task_struct *current = get_current();
  if (current && current->parent) {
    return current->parent->pid;
  }
  return 0;
}

static long sys_getuid(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                       uint64_t a4, uint64_t a5) {
  (void)a0;
  (void)a1;
  (void)a2;
  (void)a3;
  (void)a4;
  (void)a5;

  struct task_struct *current = get_current();
  return current ? current->uid : 0;
}

static long sys_getgid(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                       uint64_t a4, uint64_t a5) {
  (void)a0;
  (void)a1;
  (void)a2;
  (void)a3;
  (void)a4;
  (void)a5;

  struct task_struct *current = get_current();
  return current ? current->gid : 0;
}

static long sys_gettid(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                       uint64_t a4, uint64_t a5) {
  (void)a0;
  (void)a1;
  (void)a2;
  (void)a3;
  (void)a4;
  (void)a5;

  struct task_struct *current = get_current();
  return current ? current->pid : -1;
}

/* Userspace heap management - dedicated region for userspace processes */
#define USER_HEAP_START 0x10000000UL /* 256MB mark */
#define USER_HEAP_SIZE 0x04000000UL  /* 64MB heap */

static long sys_brk(uint64_t brk, uint64_t a1, uint64_t a2, uint64_t a3,
                    uint64_t a4, uint64_t a5) {
  (void)a1;
  (void)a2;
  (void)a3;
  (void)a4;
  (void)a5;

  struct mm_struct *mm = current_mm();
  if (!mm) {
    return -ENOMEM;
  }

  /* If brk is 0 or less than start, return current brk */
  if (brk == 0 || brk < USER_HEAP_START) {
    return mm->brk;
  }

  /* Check bounds */
  if (brk > USER_HEAP_START + USER_HEAP_SIZE / 2) {
    /* Would overlap with mmap region */
    return mm->brk;
  }

  if (brk > mm->brk) {
    uint64_t map_start = (mm->brk + 4095UL) & ~4095UL;
    uint64_t map_end = (brk + 4095UL) & ~4095UL;
    if (map_end > map_start &&
        vmm_map_user_range(mm, map_start, map_end - map_start,
                           VM_READ | VM_WRITE | VM_USER) < 0) {
      return mm->brk;
    }
  }

  mm->brk = brk;
  return mm->brk;
}

static long sys_mmap(uint64_t addr, uint64_t len, uint64_t prot, uint64_t flags,
                     uint64_t fd, uint64_t offset) {
  (void)addr;
  (void)prot;
  (void)offset;

/* Only support anonymous mappings for now */
#define MAP_ANONYMOUS 0x20
  if (!(flags & MAP_ANONYMOUS) || (int64_t)fd != -1) {
    printk(KERN_DEBUG "sys_mmap: only anonymous mappings supported\n");
    return -ENOSYS;
  }

  if (len == 0) {
    return -EINVAL;
  }
  if (len > UINT64_MAX - 4095UL) {
    return -ENOMEM;
  }

  struct mm_struct *mm = current_mm();
  if (!mm) {
    return -ENOMEM;
  }

  len = (len + 4095UL) & ~4095UL;

  /* Check bounds */
  if (mm->mmap_current > USER_HEAP_START + USER_HEAP_SIZE - len) {
    printk(KERN_WARNING "sys_mmap: out of memory\n");
    return -ENOMEM;
  }

  /* Allocate from mmap region */
  uint64_t result = mm->mmap_current;
  if (vmm_map_user_range(mm, result, len, VM_READ | VM_WRITE | VM_USER) < 0) {
    return -ENOMEM;
  }
  mm->mmap_current += len;

  return result;
}

static long sys_munmap(uint64_t addr, uint64_t len, uint64_t a2, uint64_t a3,
                       uint64_t a4, uint64_t a5) {
  (void)a2;
  (void)a3;
  (void)a4;
  (void)a5;

  struct mm_struct *mm = current_mm();
  if (!mm) {
    return -ENOMEM;
  }
  if (len == 0) {
    return -EINVAL;
  }
  if (len > UINT64_MAX - 4095UL || addr > UINT64_MAX - len) {
    return -EINVAL;
  }

  len = (len + 4095UL) & ~4095UL;
  addr &= ~4095UL;
  if (addr > UINT64_MAX - len) {
    return -EINVAL;
  }
  if (addr < mm->mmap_base || addr + len > USER_HEAP_START + USER_HEAP_SIZE) {
    return -EINVAL;
  }

  return vmm_unmap_user_range(mm, addr, len);
}

static long sys_clone(uint64_t flags, uint64_t stack, uint64_t ptid,
                      uint64_t tls, uint64_t ctid, uint64_t a5) {
  (void)flags;
  (void)stack;
  (void)ptid;
  (void)tls;
  (void)ctid;
  (void)a5;

  /* Stub - not implemented */
  return -ENOSYS;
}

/* Forward declarations for ELF loader */
extern int elf_validate(const void *data, size_t size);
extern uint64_t elf_calc_size(const void *data, size_t size);
extern int elf_load_at(const void *data, size_t size, uint64_t load_base,
                       void *info);

static long sys_execve(uint64_t filename, uint64_t argv, uint64_t envp,
                       uint64_t a3, uint64_t a4, uint64_t a5) {
  (void)argv;
  (void)envp;
  (void)a3;
  (void)a4;
  (void)a5;

  const char *path = (const char *)filename;
  printk(KERN_INFO "sys_execve: loading '%s'\n", path);

  /* Open the file */
  struct file *f = vfs_open(path, O_RDONLY, 0);
  if (!f) {
    printk(KERN_ERR "sys_execve: cannot open '%s'\n", path);
    return -ENOENT;
  }

  /* Get file size via dentry->inode */
  size_t file_size = 0;
  if (f->f_dentry && f->f_dentry->d_inode) {
    file_size = f->f_dentry->d_inode->i_size;
  }
  if (file_size == 0 || file_size > 64 * 1024 * 1024) {
    vfs_close(f);
    return -ENOEXEC;
  }

  /* Allocate buffer and read file */
  uint8_t *buf = kmalloc(file_size);
  if (!buf) {
    vfs_close(f);
    return -ENOMEM;
  }

  ssize_t bytes_read = vfs_read(f, (char *)buf, file_size);
  vfs_close(f);

  if (bytes_read != (ssize_t)file_size) {
    kfree(buf);
    return -EIO;
  }

  /* Validate ELF */
  int ret = elf_validate(buf, file_size);
  if (ret != 0) {
    printk(KERN_ERR "sys_execve: invalid ELF (error %d)\n", ret);
    kfree(buf);
    return -ENOEXEC;
  }

  /* Calculate memory needed */
  uint64_t mem_size = elf_calc_size(buf, file_size);
  if (mem_size == 0) {
    kfree(buf);
    return -ENOEXEC;
  }

  /* Load at user code base */
  typedef struct {
    uint64_t entry;
    uint64_t load_base;
    uint64_t load_size;
  } elf_load_info_t;

  elf_load_info_t info;
  ret = elf_load_at(buf, file_size, USER_CODE_BASE, &info);
  kfree(buf);

  if (ret != 0) {
    printk(KERN_ERR "sys_execve: ELF load failed\n");
    return -ENOEXEC;
  }

  printk(KERN_INFO "sys_execve: loaded at 0x%llx, entry 0x%llx\n",
         (unsigned long long)info.load_base, (unsigned long long)info.entry);

  /* Get current task and set up for userspace execution */
  struct task_struct *current = get_current();
  if (current) {
    current->flags |= PF_USER;
    current->flags &= ~PF_KTHREAD;

    /* Update task name */
    int i = 0;
    while (path[i] && i < TASK_COMM_LEN - 1) {
      current->comm[i] = path[i];
      i++;
    }
    current->comm[i] = '\0';
  }

  /* Stub - userspace execution not implemented */
  /* For now, return entry point - caller would need to jump there */
  return info.entry;
}

static long sys_uname(uint64_t buf, uint64_t a1, uint64_t a2, uint64_t a3,
                      uint64_t a4, uint64_t a5) {
  (void)a1;
  (void)a2;
  (void)a3;
  (void)a4;
  (void)a5;

  struct utsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
  };

  struct utsname *uts = (struct utsname *)buf;

  /* Copy strings (simple implementation) */
  const char *sysname = "UnixOS";
  const char *nodename = "localhost";
  const char *release = "0.1.0";
  const char *version = "0.1.0-arm64";
  const char *machine = "aarch64";
  const char *domain = "";

  for (int i = 0; i < 64 && sysname[i]; i++)
    uts->sysname[i] = sysname[i];
  uts->sysname[64] = 0;
  for (int i = 0; i < 64 && nodename[i]; i++)
    uts->nodename[i] = nodename[i];
  uts->nodename[64] = 0;
  for (int i = 0; i < 64 && release[i]; i++)
    uts->release[i] = release[i];
  uts->release[64] = 0;
  for (int i = 0; i < 64 && version[i]; i++)
    uts->version[i] = version[i];
  uts->version[64] = 0;
  for (int i = 0; i < 64 && machine[i]; i++)
    uts->machine[i] = machine[i];
  uts->machine[64] = 0;
  for (int i = 0; i < 64 && domain[i]; i++)
    uts->domainname[i] = domain[i];
  uts->domainname[64] = 0;

  return 0;
}

static long sys_sched_yield(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                            uint64_t a4, uint64_t a5) {
  (void)a0;
  (void)a1;
  (void)a2;
  (void)a3;
  (void)a4;
  (void)a5;

  schedule();
  return 0;
}

static long sys_nanosleep(uint64_t req, uint64_t rem, uint64_t a2, uint64_t a3,
                          uint64_t a4, uint64_t a5) {
  (void)rem;
  (void)a2;
  (void)a3;
  (void)a4;
  (void)a5;

  /* Stub - sleep not implemented */
  (void)req;

  return 0;
}

static long sys_not_implemented(uint64_t a0, uint64_t a1, uint64_t a2,
                                uint64_t a3, uint64_t a4, uint64_t a5) {
  (void)a0;
  (void)a1;
  (void)a2;
  (void)a3;
  (void)a4;
  (void)a5;
  return -ENOSYS;
}

/* Sound System Call */
#include "drivers/intel_hda.h"

static long sys_sound_play(uint64_t data, uint64_t samples, uint64_t channels,
                           uint64_t rate, uint64_t a4, uint64_t a5) {
  (void)a4;
  (void)a5;

  /* Check pointer validity (basic) */
  if (data < 0x10000000)
    return -EFAULT; /* Below userspace heap? Adjust check as needed */

  /* Call HDA driver */
  /* Note: data is a user virtual address. HDA DMA needs physical.
     However, our kernel mapping is currently flat/identity or we mapped
     userspace? The syscall receives arguments. pointer is userspace VA. Current
     'kmalloc' logic in HDA uses a kernel buffer and copies data. So we need to
     access user memory. For now, assuming shared address space or we can read
     it.
  */

  return intel_hda_play_pcm((const void *)data, (uint32_t)samples,
                            (uint8_t)channels, (uint32_t)rate);
}

/* ===================================================================== */
/* Syscall initialization */
/* ===================================================================== */

void syscall_init(void) {
  printk(KERN_INFO "SYSCALL: Initializing system call table\n");

  /* Initialize all to not implemented */
  for (int i = 0; i < NR_syscalls; i++) {
    syscall_table[i] = sys_not_implemented;
  }

  /* Register implemented syscalls */
  syscall_table[SYS_read] = sys_read;
  syscall_table[SYS_write] = sys_write;
  syscall_table[SYS_openat] = sys_openat;
  syscall_table[SYS_close] = sys_close;
  syscall_table[SYS_lseek] = sys_lseek;
  syscall_table[SYS_exit] = sys_exit;
  syscall_table[SYS_exit_group] = sys_exit_group;
  syscall_table[SYS_getpid] = sys_getpid;
  syscall_table[SYS_getppid] = sys_getppid;
  syscall_table[SYS_getuid] = sys_getuid;
  syscall_table[SYS_geteuid] = sys_getuid;
  syscall_table[SYS_getgid] = sys_getgid;
  syscall_table[SYS_getegid] = sys_getgid;
  syscall_table[SYS_gettid] = sys_gettid;
  syscall_table[SYS_brk] = sys_brk;
  syscall_table[SYS_mmap] = sys_mmap;
  syscall_table[SYS_munmap] = sys_munmap;
  syscall_table[SYS_clone] = sys_clone;
  syscall_table[SYS_execve] = sys_execve;
  syscall_table[SYS_uname] = sys_uname;
  syscall_table[SYS_sched_yield] = sys_sched_yield;
  syscall_table[SYS_nanosleep] = sys_nanosleep;

  printk(KERN_INFO "SYSCALL: System call table initialized\n");
}

/* ===================================================================== */
/* Syscall dispatcher */
/* ===================================================================== */

long handle_syscall(struct pt_regs *regs) {
  /* ARM64 syscall convention:
   * x8 = syscall number
   * x0-x5 = arguments
   * x0 = return value
   */

  uint64_t nr = regs->regs[8];

  if (nr >= NR_syscalls) {
    printk(KERN_WARNING "SYSCALL: Invalid syscall number %llu\n",
           (unsigned long long)nr);
    return -ENOSYS;
  }

  syscall_fn_t fn = syscall_table[nr];

  return fn(regs->regs[0], regs->regs[1], regs->regs[2], regs->regs[3],
            regs->regs[4], regs->regs[5]);
}

/* ===================================================================== */
/* Exception handler */
/* ===================================================================== */

void handle_sync_exception(struct pt_regs *regs) {
  /* Read exception syndrome register - architecture specific */
  uint32_t ec, iss;

#ifdef ARCH_ARM64
  uint64_t esr;
  asm volatile("mrs %0, esr_el1" : "=r"(esr));

  ec = (esr >> 26) & 0x3F; /* Exception class */
  iss = esr & 0x1FFFFFF;   /* Instruction specific syndrome */
#elif defined(ARCH_X86_64) || defined(ARCH_X86)
  /* x86 uses interrupt numbers instead of ESR */
  ec = 0; /* Not used on x86 */
  iss = 0;
#endif

  switch (ec) {
  case 0x15: /* SVC instruction from AArch64 */
    /* System call - handled separately */
    break;

  case 0x20: /* Instruction abort from lower EL */
  case 0x21: /* Instruction abort from same EL */
    printk(KERN_EMERG "Instruction abort at PC=0x%llx\n",
           (unsigned long long)regs->pc);
    panic("Instruction abort");
    break;

  case 0x24: /* Data abort from lower EL */
  case 0x25: /* Data abort from same EL */
  {
#ifdef ARCH_ARM64
    uint64_t far;
    asm volatile("mrs %0, far_el1" : "=r"(far));
    printk(KERN_EMERG "Data abort at PC=0x%llx, FAR=0x%llx\n",
           (unsigned long long)regs->pc, (unsigned long long)far);
#elif defined(ARCH_X86_64) || defined(ARCH_X86)
    uint64_t cr2;
    asm volatile("mov %%cr2, %0" : "=r"(cr2));
    printk(KERN_EMERG "Page fault at PC=0x%llx, CR2=0x%llx\n",
           (unsigned long long)regs->pc, (unsigned long long)cr2);
#endif
    panic("Data abort");
  } break;

  case 0x00: /* Unknown reason */
    printk(KERN_EMERG "Unknown exception at PC=0x%llx\n",
           (unsigned long long)regs->pc);
    panic("Unknown exception");
    break;

  default:
    printk(KERN_EMERG "Unhandled exception class 0x%x, ISS=0x%x\n", ec, iss);
    printk(KERN_EMERG "PC=0x%llx\n", (unsigned long long)regs->pc);
    panic("Unhandled exception");
    break;
  }
}
