#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#define PAGE_SIZE 4096
#define MAX_PATH_LEN 128
#define BUFFER_SIZE 256

void print_page_state(uint64_t vaddr_start, uint64_t entry) {
    if (entry == 0) {
        return;
    }
    int present = (entry & (1ULL << 63)) != 0;
    int swapped = (entry & (1ULL << 62)) != 0;
    uint64_t pfn = entry & 0x7FFFFFFFFFFFFF;
    printf("\t0x%-16lx : ", vaddr_start);
    if (present) {
        printf("presented, pfn 0x%lx\n", pfn);
    } else if (swapped) {
        printf("swapped, offset 0x%lx\n", pfn);
    } else {
        printf("niether presented nor swapped\n");
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <pid>\n", argv[0]);
        return 1;
    }

    int pid = atoi(argv[1]);

    char maps_path[MAX_PATH_LEN];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *maps_fd = fopen(maps_path, "r");
    if (!maps_fd) {
        perror("Error opening maps");
        return 1;
    }

    char pagemap_path[MAX_PATH_LEN];
    snprintf(pagemap_path, sizeof(pagemap_path), "/proc/%d/pagemap", pid);
    int pagemap_fd = open(pagemap_path, O_RDONLY);
    if (pagemap_fd < 0) {
        perror("Error openning pagemap");
        fclose(maps_fd);
        return 1;
    }

    char line[BUFFER_SIZE];
    while (fgets(line, sizeof(line), maps_fd)) {
        uint64_t start_addr, end_addr;
        if (sscanf(line, "%lx-%lx", &start_addr, &end_addr) != 2) {
            continue;
        }
        printf("0x%-16lx - 0x%-16lx : \n", start_addr, end_addr);

        uint64_t start_page = start_addr / PAGE_SIZE;
        uint64_t num_pages = (end_addr - start_addr) / PAGE_SIZE;

        for (uint64_t i = 0; i < num_pages; i++) {
            uint64_t page_number = start_page + i;
            uint64_t vaddr_start = page_number * PAGE_SIZE;
            uint64_t offset = page_number * 8;

            uint64_t entry;
            if (pread(pagemap_fd, &entry, 8, offset) != 8) {
                //fprintf(stderr, "  Page 0x%016lx : couldn't read\n", vaddr_start);
                continue;
            }

            //printf("  Page 0x%016lx: ", vaddr_start);
            print_page_state(vaddr_start, entry);
        }
    }

    fclose(maps_fd);
    close(pagemap_fd);
    return 0;
}
