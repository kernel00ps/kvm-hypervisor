#define _GNU_SOURCE
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
#include <string.h>
#include <stdbool.h>

#define MEM_BASE 0x100000
int pg;
int mem;
#define PDE64_PRESENT 1
#define PDE64_RW (1U << 1)
#define PDE64_USER (1U << 2)
#define PDE64_PS (1U << 7)

// CR4
#define CR4_PAE (1U << 5)

// CR0
#define CR0_PE 1u
#define CR0_PG (1U << 31)

#define EFER_LME (1U << 8)
#define EFER_LMA (1U << 10)

#define FILENAME_LEN 50

int global_vm_id = 0;

struct vm {
	int kvm_fd;
	int vm_fd;
	int vcpu_fd;
	char *mem;
	struct kvm_run *kvm_run;
    int id;
};

typedef struct List {
    FILE* fd;
    char* name;
    struct List* next;
    char op;
    bool global;
    int cur;
} List;

List* ListShared;

void add_node(List** head, char* filename)
{
     List* node = (List*)malloc(sizeof(List));
     node->fd=fopen(filename, "r");
    node->name = filename;
    node->global=true;
    node->next = *head;
    *head = node;
}

bool is_in(List* head, char* filename) {
    for(List* cur = head; cur; cur = cur->next) {
        if(!strcmp(filename, cur->name))
            return true;
    }
    return false;
}

List* find_in_open(List* head, char* filename) {
    for(List* cur = head; cur; cur = cur->next) {
        if(!strcmp(filename, cur->name))
            return cur;
    }
    return NULL;
}

void open_file(List* head, char* filename) {
    List* node = (List*)malloc(sizeof(List));
    node->name = filename;
    node->fd = fopen(filename, "w");
    node->next = head;
    node->cur=0;
    head = node;
}

void close_file(List* head, char* filename) {
    List* prev = NULL;
    for(List* cur = head; cur; cur = cur->next) {
        if(!strcmp(filename, cur->name)) { //found it
            prev = cur->next;
            fclose(cur->fd);
            free(cur);
            break;
        }
        prev = cur;
    }
}

int init_vm(struct vm *vm, size_t mem_size) {

    vm->id = global_vm_id++;

	struct kvm_userspace_memory_region region;
	int kvm_run_mmap_size;

	vm->kvm_fd = open("/dev/kvm", O_RDWR);
	if (vm->kvm_fd < 0) {
		perror("open /dev/kvm");
		return -1;
	}

	vm->vm_fd = ioctl(vm->kvm_fd, KVM_CREATE_VM, 0);
	if (vm->vm_fd < 0) {
		perror("KVM_CREATE_VM");
		return -1;
	}

	vm->mem = mmap(NULL, mem_size, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (vm->mem == MAP_FAILED) {
		perror("mmap mem");
		return -1;
	}

	region.slot = 0;
	region.flags = 0;
	region.guest_phys_addr = 0;
	region.memory_size = mem_size;
	region.userspace_addr = (unsigned long)vm->mem;
    if (ioctl(vm->vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
		perror("KVM_SET_USER_MEMORY_REGION");
        return -1;
	}

	vm->vcpu_fd = ioctl(vm->vm_fd, KVM_CREATE_VCPU, 0);
    if (vm->vcpu_fd < 0) {
		perror("KVM_CREATE_VCPU");
        return -1;
	}

	kvm_run_mmap_size = ioctl(vm->kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (kvm_run_mmap_size <= 0) {
		perror("KVM_GET_VCPU_MMAP_SIZE");
		return -1;
	}

	vm->kvm_run = mmap(NULL, kvm_run_mmap_size, PROT_READ | PROT_WRITE,
			     MAP_SHARED, vm->vcpu_fd, 0);
	if (vm->kvm_run == MAP_FAILED) {
		perror("mmap kvm_run");
		return -1;
	}

	return 0;
}

int num_of_shared;

static void setup_64bit_code_segment(struct kvm_sregs *sregs) {
	struct kvm_segment seg = {
		.base = 0,
		.limit = 0xffffffff,
		.present = 1, // Prisutan ili učitan u memoriji
		.type = 11, // Code: execute, read, accessed
		.dpl = 0, // Descriptor Privilage Level: 0 (0, 1, 2, 3)
		.db = 0, // Default size - ima vrednost 0 u long modu
		.s = 1, // Code/data tip segmenta
		.l = 1, // Long mode - 1
		.g = 1, // 4KB granularnost
	};

	sregs->cs = seg;

	seg.type = 3; // Data: read, write, accessed
	sregs->ds = sregs->es = sregs->fs = sregs->gs = sregs->ss = seg;
}

static void setup_long_mode(struct vm *vm, struct kvm_sregs *sregs) {

	int pt_bru = mem/pg;

	uint64_t page = 0;
	uint64_t pml4_addr = 0x1000;
	uint64_t *pml4 = (void *)(vm->mem + pml4_addr);

	uint64_t pdpt_addr = 0x2000;
	uint64_t *pdpt = (void *)(vm->mem + pdpt_addr);

	uint64_t pd_addr = 0x3000;
	uint64_t *pd = (void *)(vm->mem + pd_addr);

	uint64_t pt_addr = 0x4000;
	uint64_t *pt = (void *)(vm->mem + pt_addr);

	pml4[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pdpt_addr;
	pdpt[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pd_addr;

	if(pg == 0x200000) {
		for(int i = 0; i < mem/pg; i ++)
			pd[i] = PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS;
	}
	else {
		for(int i = 0; i < 1.0 * mem / pg / 512; i++) {
			pd[i] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pt_addr + i * 0x1000;
	//		printf("pd[%d] - %d\n", i, pt_addr + i * 0x1000);
    }
		
		for(int i = 0; i < pt_bru; i++) {
			pt[i] = page | PDE64_PRESENT | PDE64_RW | PDE64_USER;
	//		printf("pt[%d] - %d\n", i, page);
			page += pg;
		}
	}

	sregs->cr3  = pml4_addr; 
	sregs->cr4  = CR4_PAE; // "Physical Address Extension" mora biti 1 za long mode.
	sregs->cr0  = CR0_PE | CR0_PG; // Postavljanje "Protected Mode" i "Paging" 
	sregs->efer = EFER_LME | EFER_LMA; // Postavljanje  "Long Mode Active" i "Long Mode Enable"

	setup_64bit_code_segment(sregs);
}

void* run_vm(void *arg) {

    int ret = 0;
    struct vm* vm = (struct vm*)arg;
    struct List* ListOpen = NULL;
    struct List* cur_file = NULL;
    int stop = 0;
    int cnt = 0;
    int cntorg=0;
    bool started = false;
    bool curRead = false;
    bool curWrite = false;
    bool got_filename = false;
    bool command_fetched = false;
    bool finished = false;
    char op_code;
    char filename[FILENAME_LEN] = "";
    char original_name[FILENAME_LEN] = "";
    //int tid = (int) gettid();

    while(stop == 0) {
		ret = ioctl(vm->vcpu_fd, KVM_RUN, 0);
		if (ret == -1) {
            printf("KVM_RUN failed\n");
            return NULL;
        }

		switch (vm->kvm_run->exit_reason) {
			case KVM_EXIT_IO:
				if (vm->kvm_run->io.direction == KVM_EXIT_IO_OUT && vm->kvm_run->io.port == 0xE9\
					&& vm->kvm_run->io.size == 1 && vm->kvm_run->io.count == 1) {
					char *p = (char *)vm->kvm_run;
					printf("%c", *(p + vm->kvm_run->io.data_offset));
				}
				else if(vm->kvm_run->io.direction == KVM_EXIT_IO_IN && vm->kvm_run->io.port == 0xE9\
					&& vm->kvm_run->io.size == 1 && vm->kvm_run->io.count == 1) {
						char input_char = getchar();
						char* p = (char*)vm->kvm_run;
						*(p + vm->kvm_run->io.data_offset) = input_char;
				}
                else if (vm->kvm_run->io.direction == KVM_EXIT_IO_OUT && vm->kvm_run->io.port == 0x0278\
                    && vm->kvm_run->io.size == 1 && vm->kvm_run->io.count == 1) {
					char* p = (char *)vm->kvm_run;
                    char* input = p + vm->kvm_run->io.data_offset;

                    if(!started) {
                        started = true;
					    op_code = *input;
                        printf("operation code: %c\n", op_code);
                        original_name[0]='\0';
                        cntorg=0;
                        finished = false;
                        got_filename = false;
                        filename[0]='\0';
                        cnt=0;

                        for(int i; i<strlen(filename); i++) {
                               if(filename[i]!='\0') cnt++;
                               else break;
                        }
                    }
                    else {  
                        printf("input: %c\n", *input);
                        // reading filename
                        if(strcmp(input, " ") && strcmp(input, "|") && !got_filename)
                        {
                            filename[cnt++] = *input; 
                            original_name[cntorg++]= *input; 
                            printf("%s", original_name);
                        }
                        // selecting operation
                        if(!strcmp(input, "|"))
                        {
                            got_filename = true;
                            if(op_code=='r') curRead=true;
                            else if(op_code=='w') curWrite=true;
                        }
                        else if(!strcmp(input, "/"))
                        {
                           started=false;
                           filename[0]='\0';
                        }
                        else if(got_filename && !finished) {
                        switch(op_code)
                        {
                         case 'o': //open
                            if(!is_in(ListOpen, filename)){ 
                                List* node = (List*)malloc(sizeof(List));
                                node->name = filename;
                                node->fd = fopen(filename, "w");
                                node->next = ListOpen;
                                node->cur=0;
                                ListOpen = node;
                                cur_file = ListOpen;}
                                break;        
                        
                         case 'w': 
                            if(is_in(ListOpen, filename))
                            {
                                cur_file=find_in_open(ListOpen, filename);
                                if(cur_file!=NULL) 
                                {
                                    fseek(cur_file->fd, cur_file->cur, 0);
                                    if(cur_file->fd==NULL)
                                    fputc(*input, cur_file->fd);
                                    cur_file->cur++;
                                }
                            }
                            else if(is_in(ListOpen, original_name))
                            {
                                List* node = (List*)malloc(sizeof(List));
                                node->name = filename;
                                List* shared = find_in_open(ListShared, original_name);
                                node->fd = fopen(filename, "w");
                                char offset;
                                do {
                                    fputc(offset,node->fd);
                                } while ((offset=fgetc(shared->fd))!= EOF);
                                node->next = ListOpen;
                                node->cur=0;
                                ListOpen = node;
                                cur_file = ListOpen;
                                fseek(cur_file->fd, cur_file->cur, 0);
                                fputc(*input, cur_file->fd);
                                cur_file->cur++;
                            }
                            else if(is_in(ListShared, original_name))  
                            {
                                List* node = (List*)malloc(sizeof(List));
                                node->name = filename;
                                List* shared = find_in_open(ListShared, original_name);
                                node->fd = fopen(filename, "w");
                                char offset;
                                node->cur=0;
                                while ((offset=fgetc(shared->fd))!=EOF)
                                {
                                    fputc(offset, node->fd);
                                    node->cur=node->cur+1;
                                } 
                                node->cur=node->cur-1;
                                node->next = ListOpen;
                               //node->cur=0;
                                ListOpen = node;
                                cur_file = ListOpen;
                                fseek(cur_file->fd, cur_file->cur, 0);
                                    fputc(*input, cur_file->fd);
                                    cur_file->cur++;
                            }            
                            else if(!is_in(ListOpen, filename))
                            {
                                List* node = (List*)malloc(sizeof(List));
                                node->name = filename;
                                node->fd = fopen(filename, "w");
                                node->next = ListOpen;
                                node->cur=0;
                                ListOpen = node;
                                cur_file = ListOpen;
                                fseek(cur_file->fd, cur_file->cur, 0);
                                fputc(*input, cur_file->fd);
                                cur_file->cur++;
                            }
 
                         break;

                        case 'c': //close
                            close_file(ListOpen, filename);
                        break;
                    }
                    }
                    }             
                    
				}
				else if(vm->kvm_run->io.direction == KVM_EXIT_IO_IN && vm->kvm_run->io.port == 0x0278\
					&& vm->kvm_run->io.size == 1 && vm->kvm_run->io.count == 1) {
                        if(op_code=='r')
                        {   if(is_in(ListOpen, original_name))
                              {
                                cur_file=find_in_open(ListOpen, original_name);
                                fseek(cur_file->fd, cur_file->cur, 0);
                                char file_char =  fgetc(cur_file->fd);
                                if(file_char==EOF)
                                  {
                                     cur_file->cur=-1;
                                     started=false;
                                     filename[0]='\0';
                                  }
                                cur_file->cur++;
						        char* p = (char*)vm->kvm_run;
						        *(p + vm->kvm_run->io.data_offset) = file_char;
                              }
                            else if(is_in(ListOpen, filename))
                            {
                                cur_file=find_in_open(ListOpen, filename);
                                fseek(cur_file->fd, cur_file->cur, 0);
                                char file_char =  fgetc(cur_file->fd);
                                if(file_char==EOF)
                                  {
                                     cur_file->cur=-1;
                                     started=false;
                                     filename[0]='\0';
                                  }
                                cur_file->cur++;
						        char* p = (char*)vm->kvm_run;
						        *(p + vm->kvm_run->io.data_offset) = file_char;
                              }
                            else if(is_in(ListShared, original_name))  
                            {
                                List* node = (List*)malloc(sizeof(List));
                                node->name = original_name;
                                List* shared = find_in_open(ListShared, original_name);
                                node->fd = shared->fd;
                                node->next = ListOpen;
                                node->cur=0;
                                ListOpen = node;
                                cur_file = ListOpen;
                                fseek(cur_file->fd, cur_file->cur, 0);
                                char file_char = fgetc(cur_file->fd);
                                if(file_char==EOF)
                                  {
                                     cur_file->cur=-1;
                                     started=false;
                                     filename[0]='\0';
                                  }
                                cur_file->cur++;
						        char* p = (char*)vm->kvm_run;
						        *(p + vm->kvm_run->io.data_offset) = file_char;
                            }            
                            else if(!is_in(ListOpen, filename))
                            {
                                List* node = (List*)malloc(sizeof(List));
                                node->name = filename;
                                node->fd = fopen(filename, "w");
                                node->next = ListOpen;
                                node->cur=0;
                                ListOpen = node;
                                cur_file = ListOpen;
                                fseek(cur_file->fd, cur_file->cur, 0);
                                char file_char =  fgetc(cur_file->fd);
                                if(file_char==EOF)
                                  {
                                     cur_file->cur=-1;
                                     started=false;
                                     filename[0]='\0';
                                  }
                                cur_file->cur++;
						        char* p = (char*)vm->kvm_run;
						        *(p + vm->kvm_run->io.data_offset) = file_char;
                            }
                        }
				}
				continue;
				
			case KVM_EXIT_HLT:
				printf("KVM_EXIT_HLT\n");
				stop = 1;
				break;
			case KVM_EXIT_INTERNAL_ERROR:
				printf("Internal error: suberror = 0x%x\n", vm->kvm_run->internal.suberror);
				stop = 1;
				break;
			case KVM_EXIT_SHUTDOWN:
				printf("Shutdown\n");
				stop = 1;
				break;
			default:
				printf("Exit reason: %d\n", vm->kvm_run->exit_reason);
				break;
    	}
  	}
}

int main(int argc, char *argv[])
{
    int guests = 0;
    int shared = 0;

    for(int i = 6; i < argc; i ++) {
        printf("argv: %s\n", argv[i]);
        if(!(strcmp(argv[i], "-f") && strcmp(argv[i], "--file")))
            break;
        guests++;
    }
    shared = argc - guests - 7;
    printf("shared: %d, guests: %d\n", shared, guests);

    if(guests == 0) {
        printf("no guests provided\n");
        return -1;
    }

    pthread_t threads[guests];
	struct vm vms[guests];
	struct kvm_sregs sregs[guests];
	struct kvm_regs regs[guests];
	int stop = 0;
    num_of_shared = shared;
	FILE* img[guests];
    char* shared_names[shared];
  //  List* node;
    for(int i = 0; i < shared; i++)
        add_node(&ListShared, argv[7 + guests + i]);

	if (argc < 7) {
    	//printf("The program requests an image to run: %s <guest-image>\n", argv[0]);
		printf("broj argumenata nije ok!\n");
    	return 1;
  	}

	mem = atoi(argv[2]) * MEM_BASE;
	pg = atoi(argv[4]);
	pg = (pg == 4) ? 0x1000 : 0x200000;

    for(int i = 0; i < guests; i++) {

        if (init_vm(&vms[i], mem)) {
                printf("Failed to init the VM\n");
                return -1;
        }
        if (ioctl(vms[i].vcpu_fd, KVM_GET_SREGS, &sregs[i]) < 0) {
            perror("KVM_GET_SREGS");
            return -1;
        }
        setup_long_mode(&vms[i], &sregs[i]);

        if (ioctl(vms[i].vcpu_fd, KVM_SET_SREGS, &sregs[i]) < 0) {
            perror("KVM_SET_SREGS");
            return -1;
        }
        memset(&regs[i], 0, sizeof(regs));
        regs[i].rflags = 2;
        regs[i].rip = 0;
        regs[i].rsp = mem;

        if (ioctl(vms[i].vcpu_fd, KVM_SET_REGS, &regs[i]) < 0) {
            perror("KVM_SET_REGS");
            return -1;
        }

        img[i] = fopen(argv[6 + i], "r");
        if (img[i] == NULL) {
            printf("Can not open binary file\n");
            return -1;
        }

        char *p = vms[i].mem;
        while(feof(img[i]) == 0) {
            int r = fread(p, 1, 1024, *(img + i));
            p += r;
        }
  	    fclose(img[i]);
    }

    for(int i = 0; i < guests; i++) 
        pthread_create(&threads[i], NULL, run_vm, &vms[i]);
	
    for(int i = 0; i < guests; i++)
        pthread_join(threads[i], NULL);

}
