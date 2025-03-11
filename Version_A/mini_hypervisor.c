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

#define MEM_BASE_MULTIPLIER 0x100000
#define PAGE_SIZE_4KB 0x1000
#define PAGE_SIZE_2MB 0x200000
int page_size;
int mem;

// mem layout addresses for PT structures
#define PML4_ADDR 0x1000
#define PDPT_ADDR 0x2000
#define PD_ADDR 0x3000
#define PT_ADDR 0x4000

// 64-bit page entry bits
#define PDE64_PRESENT 1
#define PDE64_RW (1U << 1)
#define PDE64_USER (1U << 2)
#define PDE64_PS (1U << 7)

// CR4 flags
#define CR4_PAE (1U << 5)

// CR0 flags
#define CR0_PE 1u
#define CR0_PG (1U << 31)

// EFER flags
#define EFER_LME (1U << 8)
#define EFER_LMA (1U << 10)

// I/O port for guest communication
#define IO_PORT 0xE9

struct vm {
	int kvm_fd;
	int vm_fd;
	int vcpu_fd;
	char *mem;
	struct kvm_run *kvm_run;
	size_t kvm_run_mmap_size;
};


// resource cleanup
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
		.base = 0,
		.limit = 0xffffffff,
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
	int pt_entry = mem/page_size;

	uint64_t page = 0;

	// pointers to page tables
	uint64_t *pml4 = (void *)(vm->mem + PML4_ADDR);
	uint64_t *pdpt = (void *)(vm->mem + PDPT_ADDR);
	uint64_t *pd = (void *)(vm->mem + PD_ADDR);
	uint64_t *pt = (void *)(vm->mem + PT_ADDR);

	pml4[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | PDPT_ADDR;
	pdpt[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | PD_ADDR;

	// when using 2MB pages ---> PD is the last level
	if(page_size == PAGE_SIZE_2MB) {
		for(int i = 0; i < mem/page_size; i++) {
			pd[i] = page | PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS;
			page += page_size;
		}
	}
	// when using 4KB pages ---> PT is the last level
	else {
		for(int i = 0; i < 1.0 * mem/page_size/512; i++) {
			pd[i] = PDE64_PRESENT | PDE64_RW | PDE64_USER | PT_ADDR + i * 0x1000;
		}
		
		for(int i = 0; i < pt_entry; i++) {
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

int main(int argc, char *argv[])
{
	int opt;
    int memory_arg = 0;
    int page_arg = 0;
    char *guest_img_path = NULL;

    // define long options
    static struct option long_options[] = {
        {"memory", required_argument, 0, 'm'},
        {"page",   required_argument, 0, 'p'},
        {"guest",  required_argument, 0, 'g'},
        {0, 0, 0, 0}
    };

    // parse command line arguments
    while ((opt = getopt_long(argc, argv, "m:p:g:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'm':
                memory_arg = atoi(optarg);
                break;
            case 'p':
                page_arg = atoi(optarg);
                break;
            case 'g':
                guest_img_path = optarg;
                break;
            default:
                fprintf(stderr, "Usage: %s --memory <4|2> --page <4|2> --guest <path>\n", argv[0]);
                //exit(EXIT_FAILURE);
				return 1;
        }
    }
	// check argument validity
    if (memory_arg == 0 || (page_arg != 4 && page_arg != 2) || (memory_arg != 2 && memory_arg != 4 && memory_arg != 8) || guest_img_path == NULL) {
        fprintf(stderr, "Usage: %s --memory <4|2> --page <4|2> --guest <path>\n", argv[0]);
        //exit(EXIT_FAILURE);
		return 1;
    }

    printf("hypervisor started\n");
	struct vm vm;
	struct kvm_sregs sregs;
	struct kvm_regs regs;
	int stop = 0;
	int ret = 0;
	FILE* img = NULL;

	// file descriptors invalid until set
	vm.kvm_fd = vm.vm_fd = vm.vcpu_fd = -1;

	vm.mem = NULL;

	// parse and calculate mem and page size
	mem = atoi(argv[2]) * MEM_BASE_MULTIPLIER;
	page_size = atoi(argv[4]);
	page_size = (page_size == 4) ? PAGE_SIZE_4KB : PAGE_SIZE_2MB;
	
	if (init_vm(&vm, mem)) {
		printf("Failed to init the VM\n");
		cleanup_vm(&vm, mem);
		return -1;
	}

	// get current special registers
	if (ioctl(vm.vcpu_fd, KVM_GET_SREGS, &sregs) < 0) {
		perror("KVM_GET_SREGS");
		cleanup_vm(&vm, mem);
		return -1;
	}

	setup_long_mode(&vm, &sregs);

    if (ioctl(vm.vcpu_fd, KVM_SET_SREGS, &sregs) < 0) {
		perror("KVM_SET_SREGS");
		cleanup_vm(&vm, mem);
		return -1;
	}

	// init general purpose regs
	memset(&regs, 0, sizeof(regs));
	// clear all FLAGS bits, except bit 1 which is always set
	regs.rflags = 2;
	regs.rip = 0;
	regs.rsp = mem; // stack pointer at the top of guest memory

	if (ioctl(vm.vcpu_fd, KVM_SET_REGS, &regs) < 0) {
		perror("KVM_SET_REGS");
		cleanup_vm(&vm, mem);
		return -1;
	}

	img = fopen(argv[6], "r");
	if (!img) {
		printf("Can't open binary file\n");
		cleanup_vm(&vm, mem);
		return -1;
	}

	char *mem_ptr = vm.mem;
  	while(feof(img) == 0) {
    	size_t bytes_read = fread(mem_ptr, 1, 1024, img);
		if (ferror(img)) {
        	perror("Error reading guest binary");
        	fclose(img);
        	cleanup_vm(&vm, mem);
        	return -1;
		}
    	mem_ptr += bytes_read;
  	}
  	fclose(img);

	while(!stop) {
		ret = ioctl(vm.vcpu_fd, KVM_RUN, 0);
		if (ret == -1) {
			printf("KVM_RUN failed\n");
			cleanup_vm(&vm, mem);
			return 1;
		}

		switch (vm.kvm_run->exit_reason) {
			case KVM_EXIT_IO:
				// I/O out: print a single character
				if (vm.kvm_run->io.direction == KVM_EXIT_IO_OUT && vm.kvm_run->io.port == IO_PORT\
					&& vm.kvm_run->io.size == 1 && vm.kvm_run->io.count == 1) {
					char *data_ptr = (char*)vm.kvm_run;
					putchar(*(data_ptr + vm.kvm_run->io.data_offset));
				}
				// I/O in: send a single character from input
				else if(vm.kvm_run->io.direction == KVM_EXIT_IO_IN && vm.kvm_run->io.port == IO_PORT\
					&& vm.kvm_run->io.size == 1 && vm.kvm_run->io.count == 1) {
						char input_char = getchar();
						char* data_ptr = (char*)vm.kvm_run;
						*(data_ptr + vm.kvm_run->io.data_offset) = input_char;
				}
				continue;
				
			case KVM_EXIT_HLT:
				printf("KVM_EXIT_HLT\n");
				stop = 1;
				break;
			case KVM_EXIT_INTERNAL_ERROR:
				printf("Internal error: suberror = 0x%x\n", vm.kvm_run->internal.suberror);
				stop = 1;
				break;
			case KVM_EXIT_SHUTDOWN:
				printf("Shutdown\n");
				stop = 1;
				break;
			default:
				printf("Exit reason: %d\n", vm.kvm_run->exit_reason);
				break;
    	}
  	}
	cleanup_vm(&vm, mem);
}
