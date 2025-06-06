#define _GNU_SOURCE
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <linux/kvm.h>
#include <pthread.h>
#include <stdbool.h>

#define MEM_BASE_MULTIPLIER 0x100000
#define PAGE_SIZE_4KB       0x1000
#define PAGE_SIZE_2MB       0x200000

int page_size;
int mem;

// mem layout addresses for PT structures
#define PML4_ADDR 0x1000
#define PDPT_ADDR 0x2000
#define PD_ADDR   0x3000
#define PT_ADDR   0x4000

// 64-bit page entry bits
#define PDE64_PRESENT 1
#define PDE64_RW      (1U << 1)
#define PDE64_USER    (1U << 2)
#define PDE64_PS      (1U << 7)

// CR flags
#define CR4_PAE (1U << 5)
#define CR0_PE   1u
#define CR0_PG   (1U << 31)

// EFER flags
#define EFER_LME (1U << 8)
#define EFER_LMA (1U << 10)

// maximum number of simultaneous open files per VM
#define MAX_HANDLES 32

#define FILENAME_MAX_LEN    64

#define IO_PORT_KBD         0xE9
#define IO_PORT_FILE        0x0278

struct vm {
    int kvm_fd;
    int vm_fd;
    int vcpu_fd;
    char *mem;
    struct kvm_run *kvm_run;
    size_t kvm_run_mmap_size;
};

// file that can be shared or private to a VM
typedef struct {
    char name[FILENAME_MAX_LEN];
    FILE *shared_fp; // open handle to the shared file (read or initial write cpy)
} SharedFile;

// oopen file handle (inside VM)
typedef struct {
    bool in_use;
    char name[FILENAME_MAX_LEN];
    FILE* fp;
    bool is_shared; // true if original shared file (read only)
    bool is_private; // true if private copy (writeable)
    long offset;     // current file offset
} FileHandle;

static SharedFile *shared_files = NULL;
static int num_shared = 0;

static void cleanup_vm(struct vm *vm, size_t mem_size) {
    if (vm->kvm_run && vm->kvm_run != MAP_FAILED)
        munmap(vm->kvm_run, vm->kvm_run_mmap_size);
    if (vm->mem && vm->mem != MAP_FAILED)
        munmap(vm->mem, mem_size);
    if (vm->vcpu_fd >= 0)
        close(vm->vcpu_fd);
    if (vm->vm_fd >= 0)
        close(vm->vm_fd);
    if (vm->kvm_fd >= 0)
        close(vm->kvm_fd);
}

int init_vm(struct vm *vm, size_t mem_size)
{
    struct kvm_userspace_memory_region region;

    // get file desc for KVM
    vm->kvm_fd = open("/dev/kvm", O_RDWR);
    if (vm->kvm_fd < 0) {
        perror("open /dev/kvm");
        return -1;
    }

    // get file desc for the VM
    vm->vm_fd = ioctl(vm->kvm_fd, KVM_CREATE_VM, 0);
    if (vm->vm_fd < 0) {
        perror("KVM_CREATE_VM");
        cleanup_vm(vm, mem_size);
        return -1;
    }

    // guest memory alloc
    vm->mem = mmap(NULL, mem_size, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (vm->mem == MAP_FAILED) {
        perror("mmap mem");
        cleanup_vm(vm, mem_size);
        return -1;
    }

    region.slot = 0;
    region.flags = 0;
    region.guest_phys_addr = 0;
    region.memory_size = mem_size;
    region.userspace_addr = (unsigned long)vm->mem;
    if (ioctl(vm->vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
        perror("KVM_SET_USER_MEMORY_REGION");
        cleanup_vm(vm, mem_size);
        return -1;
    }

    // VCPU file desc
    vm->vcpu_fd = ioctl(vm->vm_fd, KVM_CREATE_VCPU, 0);
    if (vm->vcpu_fd < 0) {
        perror("KVM_CREATE_VCPU");
        cleanup_vm(vm, mem_size);
        return -1;
    }

    vm->kvm_run_mmap_size = ioctl(vm->kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (vm->kvm_run_mmap_size <= 0) {
        perror("KVM_GET_VCPU_MMAP_SIZE");
        cleanup_vm(vm, mem_size);
        return -1;
    }

    vm->kvm_run = mmap(NULL, vm->kvm_run_mmap_size, PROT_READ | PROT_WRITE,
                       MAP_SHARED, vm->vcpu_fd, 0);
    if (vm->kvm_run == MAP_FAILED) {
        perror("mmap kvm_run");
        cleanup_vm(vm, mem_size);
        return -1;
    }

    return 0;
}

static void setup_64bit_code_segment(struct kvm_sregs *sregs)
{
    struct kvm_segment seg = {
        .base    = 0,
        .limit   = 0xffffffff,
        .present = 1, // segment present in memory
        .type = 11, // executable, readable, accessed
        .dpl = 0, // descriptor privilege level: 0 (0, 1, 2, 3)
        .db = 0, // default size 0 in long mode
        .s = 1, // code/data segment
        .l = 1, // 64-bit long mode enabled
        .g = 1, // 4KB granularity
    };

    sregs->cs = seg;
    seg.type = 3; // data segment: readable, writable, accessed
    sregs->ds = sregs->es = sregs->fs = sregs->gs = sregs->ss = seg;
}

static void setup_long_mode(struct vm *vm, struct kvm_sregs *sregs)
{
    int pt_entries = mem / page_size;

    uint64_t page = 0;

    // pointers to page tables

    uint64_t *pml4 = (uint64_t *)(vm->mem + PML4_ADDR);
    uint64_t *pdpt = (uint64_t *)(vm->mem + PDPT_ADDR);
    uint64_t *pd   = (uint64_t *)(vm->mem + PD_ADDR);
    uint64_t *pt   = (uint64_t *)(vm->mem + PT_ADDR);

    pml4[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | PDPT_ADDR;
    pdpt[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | PD_ADDR;

    // when using 2MB pages ---> PD is the last level
    if (page_size == PAGE_SIZE_2MB) {
        for (int i = 0; i < pt_entries; i++) {
            pd[i] = page | PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS;
            page += page_size;
        }
    }
    // when using 4KB pages ---> PT is the last level
    else {
        int pdpt_entries = (mem / page_size) / 512;
        for (int i = 0; i < pdpt_entries; i++) {
            pd[i] = PDE64_PRESENT | PDE64_RW | PDE64_USER | (PT_ADDR + i * PAGE_SIZE_4KB);
        }
        for (int i = 0; i < pt_entries; i++) {
            pt[i] = page | PDE64_PRESENT | PDE64_RW | PDE64_USER;
            page += page_size;
        }
    }

    // long mode - ctrl registers
    sregs->cr3  = PML4_ADDR; 
    sregs->cr4  = CR4_PAE; // enabling "Physical Address Extension"
    sregs->cr0  = CR0_PE | CR0_PG; // enabling "Protected Mode" and "Paging" 
    sregs->efer = EFER_LME | EFER_LMA; // enabling  "Long Mode Active" and "Long Mode Enable"

    // initialize segment registers
    setup_64bit_code_segment(sregs);
}

// create private copy of a shared file for WR operations
static FILE* make_private_copy(const char *shared_name, const char *vm_copy_name) {
    FILE *src = fopen(shared_name, "rb");
    if (!src)
        return NULL;

    FILE *dst = fopen(vm_copy_name, "wb");
    if (!dst) {
        fclose(src);
        return NULL;
    }
    int ch;
    while ((ch = fgetc(src)) != EOF) {
        fputc(ch, dst);
    }
    fclose(src);
    return dst;
}

// maintain array of handles inside each VM
typedef struct {
    FileHandle handles[MAX_HANDLES];
} VMFileTable;

// find free slot in VM’s file table
static int allocate_handle(VMFileTable *table, const char *name, FILE *fp, bool is_shared, bool is_private) {
    for (int i = 0; i < MAX_HANDLES; i++) {
        if (!table->handles[i].in_use) {
            table->handles[i].in_use     = true;
            strncpy(table->handles[i].name, name, FILENAME_MAX_LEN - 1);
            table->handles[i].name[FILENAME_MAX_LEN - 1] = '\0';
            table->handles[i].fp          = fp;
            table->handles[i].is_shared   = is_shared;
            table->handles[i].is_private  = is_private;
            table->handles[i].offset      = 0;
            return i;
        }
    }
    return -1; // no free handle
}

// look up open handle index by filename
static int find_handle_index(VMFileTable *table, const char *name) {
    for (int i = 0; i < MAX_HANDLES; i++) {
        if (table->handles[i].in_use && strcmp(table->handles[i].name, name) == 0)
            return i;
    }
    return -1;
}

// close handle
static void close_handle(VMFileTable *table, int idx) {
    if (idx < 0 || idx >= MAX_HANDLES)
        return;
    if (table->handles[idx].in_use) {
        fclose(table->handles[idx].fp);
        table->handles[idx].in_use = false;
    }
}

// check if filename is in the shared set
static int find_shared_file(const char *name) {
    for (int i = 0; i < num_shared; i++) {
        if (strcmp(shared_files[i].name, name) == 0)
            return i;
    }
    return -1;
}

void *run_vm(void *arg)
{
    int ret = 0;
    int stop = 0;
    struct vm *vm = (struct vm *)arg;
    VMFileTable  file_table = {0};

    while (!stop) {
        ret = ioctl(vm->vcpu_fd, KVM_RUN, 0);
        if (ret == -1) {
            perror("KVM_RUN failed");
            cleanup_vm(vm, mem);
            return NULL;
        }

        switch (vm->kvm_run->exit_reason) {
            case KVM_EXIT_IO:
                // KBD I/O from VM
                if (vm->kvm_run->io.direction == KVM_EXIT_IO_OUT &&
                    vm->kvm_run->io.port == IO_PORT_KBD &&
                    vm->kvm_run->io.size == 1 &&
                    vm->kvm_run->io.count == 1) {
                    char *data_ptr = (char *)vm->kvm_run;
                    putchar(*(data_ptr + vm->kvm_run->io.data_offset));
                }
                else if (vm->kvm_run->io.direction == KVM_EXIT_IO_IN &&
                         vm->kvm_run->io.port == IO_PORT_KBD &&
                         vm->kvm_run->io.size == 1 &&
                         vm->kvm_run->io.count == 1) {
                    char input_char = getchar();
                    char *data_ptr = (char *)vm->kvm_run;
                    *(data_ptr + vm->kvm_run->io.data_offset) = input_char;
                }
                // file I/O from VM
                else if (vm->kvm_run->io.direction == KVM_EXIT_IO_OUT &&
                         vm->kvm_run->io.port == IO_PORT_FILE &&
                         vm->kvm_run->io.size == 1 &&
                         vm->kvm_run->io.count == 1) {
                    // protocol from guest: first byte = op code ('o','r','w','c'),
                    // then bytes of filename (terminated by '|'), then if 'w', a data byte.
                    static char op = 0;
                    static char fname[FILENAME_MAX_LEN];
                    static int  fn_idx = 0;
                    char *p = (char *)vm->kvm_run;
                    char  b = *(p + vm->kvm_run->io.data_offset);

                    if (op == 0) {
                        // first byte: operation code
                        op = b;
                        fn_idx = 0;
                        fname[0] = '\0';
                    }
                    else if (b != '|') {
                        // building filename
                        if (fn_idx < FILENAME_MAX_LEN - 1) {
                            fname[fn_idx++] = b;
                            fname[fn_idx] = '\0';
                        }
                    }
                    else {
                        // '|' delimiter: perform operation now
                        int handle_idx = find_handle_index(&file_table, fname);
                        switch (op) {
                            case 'o': {
                                if (handle_idx != -1) {
                                    // already open, ignore
                                    break;
                                }
                                // check if filename is in shared set
                                int sidx = find_shared_file(fname);
                                FILE *fp = NULL;
                                if (sidx >= 0) {
                                    // shared file: open for RD
                                    fp = fopen(shared_files[sidx].name, "rb");
                                    if (!fp) {
                                        // if not exist create empty
                                        fp = fopen(shared_files[sidx].name, "wb+");
                                        fseek(fp, 0, SEEK_SET);
                                    }
                                    allocate_handle(&file_table, fname, fp, true, false);
                                }
                                else {
                                    // private file: create new
                                    fp = fopen(fname, "wb+");
                                    allocate_handle(&file_table, fname, fp, false, true);
                                }
                                break;
                            }
                            case 'r': {
                                if (handle_idx < 0) break;
                                FileHandle *h = &file_table.handles[handle_idx];
                                fseek(h->fp, h->offset, SEEK_SET);
                                int ch = fgetc(h->fp);
                                if (ch == EOF) ch = 0; 
                                h->offset++;
                                // return read byte back to guest
                                char *q = (char *)vm->kvm_run;
                                *(q + vm->kvm_run->io.data_offset) = (char)ch;
                                break;
                            }
                            case 'w': {
                                // next byte after '|' is data to write
                                // will be read on the next IN I/O from guest
                                break;
                            }
                            case 'c': {
                                if (handle_idx >= 0) {
                                    close_handle(&file_table, handle_idx);
                                }
                                break;
                            }
                            default:
                                break;
                        }
                        op = 0; // reset for next command
                    }
                }
                else if (vm->kvm_run->io.direction == KVM_EXIT_IO_IN &&
                         vm->kvm_run->io.port == IO_PORT_FILE &&
                         vm->kvm_run->io.size == 1 &&
                         vm->kvm_run->io.count == 1) {
                    // for WR operation: guest expects a status or just an ACK
                    // will return 0 success.
                    char *p = (char *)vm->kvm_run;
                    *(p + vm->kvm_run->io.data_offset) = (char)0;
                }
                continue;

            case KVM_EXIT_HLT:
                stop = 1;
                break;
            case KVM_EXIT_INTERNAL_ERROR:
                fprintf(stderr, "Internal error: suberror = 0x%x\n",
                        vm->kvm_run->internal.suberror);
                stop = 1;
                break;
            case KVM_EXIT_SHUTDOWN:
                stop = 1;
                break;
            default:
                stop = 1;
                break;
        }
    }

    // close any remaining open handles
    for (int i = 0; i < MAX_HANDLES; i++) {
        if (file_table.handles[i].in_use) {
            fclose(file_table.handles[i].fp);
        }
    }
    cleanup_vm(vm, mem);
    return NULL;
}

int main(int argc, char *argv[])
{
    int opt;
    int memory_arg = 0;
    int page_arg = 0;
    char **guest_paths = NULL;
    int max_guests = 0;
    int guests_parsed = 0;

    char **shared_paths = NULL;
    int max_shared = 0;
    int shared_parsed = 0;

    // define long options
    static struct option long_options[] = {
        {"memory", required_argument, 0, 'm'},
        {"page",   required_argument, 0, 'p'},
        {"guest",  required_argument, 0, 'g'},
        {"file",   required_argument, 0, 'f'},
        {0, 0, 0, 0}
    };

    // parse command-line arguments
    while ((opt = getopt_long(argc, argv, "m:p:g:f:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'm':
                memory_arg = atoi(optarg);
                break;
            case 'p':
                page_arg = atoi(optarg);
                break;
            case 'g':
                // allocate/expand guest_paths array by 1
                if (guests_parsed >= max_guests) {
                    max_guests = (max_guests == 0 ? 1 : max_guests * 2);
                    guest_paths = realloc(guest_paths, max_guests * sizeof(*guest_paths));
                }
                guest_paths[guests_parsed++] = strdup(optarg);
                break;
            case 'f':
                if (shared_parsed >= max_shared) {
                    max_shared = (max_shared == 0 ? 1 : max_shared * 2);
                    shared_paths = realloc(shared_paths, max_shared * sizeof(*shared_paths));
                }
                shared_paths[shared_parsed++] = strdup(optarg);
                break;
            default:
                fprintf(stderr, "Usage: %s --memory <8|4|2> --page <4|2> --guest <img1> [--guest <img2> ...] [--file <shared1> ...]\n", argv[0]);
                return EXIT_FAILURE;
        }
    }

    int opt_end = optind; // first index of non-option args

    // absorb any leftover guest args as guests
    for (int i = opt_end; i < argc; i++) {
        if (guests_parsed >= max_guests) {
            max_guests = (max_guests == 0 ? 1 : max_guests * 2);
            guest_paths = realloc(guest_paths, max_guests * sizeof(*guest_paths));
        }
        guest_paths[guests_parsed++] = strdup(argv[i]);
    }

    if (guests_parsed == 0) {
        fprintf(stderr, "Error: at least one --guest <path> is required\n");
        return EXIT_FAILURE;
    }

    // load shared files into memory
    num_shared = shared_parsed;
    shared_files = calloc(num_shared, sizeof(*shared_files));
    for (int i = 0; i < shared_parsed; i++) {
        strncpy(shared_files[i].name, shared_paths[i], FILENAME_MAX_LEN - 1);
        shared_files[i].name[FILENAME_MAX_LEN - 1] = '\0';
        // open for read (create an empty file if missing)
        shared_files[i].shared_fp = fopen(shared_files[i].name, "rb");
        if (!shared_files[i].shared_fp) {
            shared_files[i].shared_fp = fopen(shared_files[i].name, "wb+");
        }
        rewind(shared_files[i].shared_fp);
    }

    int num_guests = guests_parsed;

    // check argument validity
    if (memory_arg == 0 ||
        (page_arg != 4 && page_arg != 2) ||
        (memory_arg != 2 && memory_arg != 4 && memory_arg != 8) ||
        num_guests < 1) {
        fprintf(stderr, "Usage: %s --memory <8|4|2> --page <4|2> --guest <img1> ... [--file <shared1> ...]\n", argv[0]);
        return EXIT_FAILURE;
    }

    // calculate mem and page size
    mem = memory_arg * MEM_BASE_MULTIPLIER;
    page_size = (page_arg == 4) ? PAGE_SIZE_4KB : PAGE_SIZE_2MB;

    printf("Hypervisor started: mem = %zuMB, page = %sKB, guests = %d, shared_files = %d\n",
           (size_t)memory_arg, (page_arg == 4) ? "4" : "2048", num_guests, num_shared);

    pthread_t threads[num_guests];
    struct vm vms[num_guests];
    struct kvm_sregs sregs[num_guests];
    struct kvm_regs regs[num_guests];
    FILE *img[num_guests];

    // initializing VMs and loading their guest images
    for (int i = 0; i < num_guests; i++) {

        // file descriptors invalid until set
        vms[i].kvm_fd = vms[i].vm_fd = vms[i].vcpu_fd = -1;
        
        vms[i].mem = NULL;

        if (init_vm(&vms[i], mem) != 0) {
            fprintf(stderr, "Failed to init VM %d\n", i);
            return EXIT_FAILURE;
        }

        if (ioctl(vms[i].vcpu_fd, KVM_GET_SREGS, &sregs[i]) < 0) {
            perror("KVM_GET_SREGS");
            cleanup_vm(&vms[i], mem);
            return EXIT_FAILURE;
        }

        setup_long_mode(&vms[i], &sregs[i]);

        if (ioctl(vms[i].vcpu_fd, KVM_SET_SREGS, &sregs[i]) < 0) {
            perror("KVM_SET_SREGS");
            cleanup_vm(&vms[i], mem);
            return EXIT_FAILURE;
        }

        // init general purpose regs
        memset(&regs[i], 0, sizeof(regs[i]));
        // clear all FLAGS bits, except bit 1 which is always set
        regs[i].rflags = 2;
        regs[i].rip = 0;
        regs[i].rsp = mem; // stack pointer at the top of guest memory

        if (ioctl(vms[i].vcpu_fd, KVM_SET_REGS, &regs[i]) < 0) {
            perror("KVM_SET_REGS");
            cleanup_vm(&vms[i], mem);
            return EXIT_FAILURE;
        }

        // open guest img file
        img[i] = fopen(guest_paths[i], "rb");
        if (!img[i]) {
            fprintf(stderr, "Can't open guest image: %s\n", guest_paths[i]);
            cleanup_vm(&vms[i], mem);
            return EXIT_FAILURE;
        }

        char *mem_ptr = vms[i].mem;
        while (!feof(img[i])) {
            size_t bytes_read = fread(mem_ptr, 1, 1024, img[i]);
            if (ferror(img[i])) {
                perror("Error reading guest binary");
                fclose(img[i]);
                cleanup_vm(&vms[i], mem);
                return EXIT_FAILURE;
            }
            mem_ptr += bytes_read;
        }
        fclose(img[i]);

        // create a thread to run this VM
        if (pthread_create(&threads[i], NULL, run_vm, &vms[i]) != 0) {
            perror("pthread_create");
            cleanup_vm(&vms[i], mem);
            return EXIT_FAILURE;
        }
    }

    // wait for all VMs to finish
    for (int i = 0; i < num_guests; i++) {
        pthread_join(threads[i], NULL);
    }

    // cleanup shared file handles
    for (int i = 0; i < num_shared; i++) {
        if (shared_files[i].shared_fp) {
            fclose(shared_files[i].shared_fp);
        }
    }
    free(shared_files);

    for (int i = 0; i < guests_parsed; i++) {
        free(guest_paths[i]);
    }
    free(guest_paths);

    for (int i = 0; i < shared_parsed; i++) {
        free(shared_paths[i]);
    }
    free(shared_paths);

}
