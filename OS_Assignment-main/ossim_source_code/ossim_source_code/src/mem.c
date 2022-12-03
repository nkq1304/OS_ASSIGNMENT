
#include "mem.h"
#include "stdlib.h"
#include "string.h"
#include <pthread.h>
#include <stdio.h>

static BYTE _ram[RAM_SIZE];

static struct {
	uint32_t proc;	// ID of process currently uses this page
	int index;	// Index of the page in the list of pages allocated
			// to the process.
	int next;	// The next page in the list. -1 if it is the last
			// page.
} _mem_stat [NUM_PAGES];

static pthread_mutex_t mem_lock;

void init_mem(void) {
	memset(_mem_stat, 0, sizeof(*_mem_stat) * NUM_PAGES);
	memset(_ram, 0, sizeof(BYTE) * RAM_SIZE);
	pthread_mutex_init(&mem_lock, NULL);
}

/* get offset of the virtual address */
static addr_t get_offset(addr_t addr) {
	return addr & ~((~0U) << OFFSET_LEN);
}

/* get the first layer index */
static addr_t get_first_lv(addr_t addr) {
	return addr >> (OFFSET_LEN + PAGE_LEN);
}

/* get the second layer index */
static addr_t get_second_lv(addr_t addr) {
	return (addr >> OFFSET_LEN) - (get_first_lv(addr) << PAGE_LEN);
}

/* Search for page table table from the a segment table */
static struct trans_table_t * get_trans_table(
		addr_t index, 	// Segment level index
		struct page_table_t * page_table) { // first level table
	
	/*
	 * TODO: Given the Segment index [index], you must go through each
	 * row of the segment table [page_table] and check if the v_index
	 * field of the row is equal to the index
	 *
	 * */

	int i;
	for (i = 0; i < page_table->size; i++) {
		// Enter your code here
		if (page_table->table[i].v_index == index)		// Compare "v_index" row i of first layer with "index"
			return page_table->table[i].next_lv;		// If equal, return trans_table_t "next_lv" row i  
	}
	return NULL;							// If as not found, return NULL

}


/* Translate virtual address to physical address. If [virtual_addr] is valid,
 * return 1 and write its physical counterpart to [physical_addr].
 * Otherwise, return 0 */
static int translate(
		addr_t virtual_addr, 	// Given virtual address
		addr_t * physical_addr, // Physical address to be returned
		struct pcb_t * proc) {  // Process uses given virtual address

	/* Offset of the virtual address */
	addr_t offset = get_offset(virtual_addr);
	/* The first layer index */
	addr_t first_lv = get_first_lv(virtual_addr);
	/* The second layer index */
	addr_t second_lv = get_second_lv(virtual_addr);
	
	/* Search in the first level */
	struct trans_table_t * trans_table = NULL;
	trans_table = get_trans_table(first_lv, proc->seg_table);
	if (trans_table == NULL) {
		return 0;
	}

	/* Translate in the second level */
	int i;
	for (i = 0; i < trans_table->size; i++) {
		if (trans_table->table[i].v_index == second_lv) {
			/* TODO: Concatenate the offset of the virtual addess
			 * to [p_index] field of trans_table->table[i] to 
			 * produce the correct physical address and save it to
			 * [*physical_addr]  */
			*physical_addr = (trans_table->table[i].p_index << OFFSET_LEN) + offset;
			return 1;
		}
	}
	return 0;	
}
addr_t alloc_mem(uint32_t size, struct pcb_t * proc) {
	pthread_mutex_lock(&mem_lock);
	addr_t ret_mem = 0;
	/* TODO: Allocate [size] byte in the memory for the
	 * process [proc] and save the address of the first
	 * byte in the allocated memory region to [ret_mem].
	 * */

	uint32_t num_pages = (size % PAGE_SIZE) ? size / PAGE_SIZE :
		size / PAGE_SIZE + 1; // Number of pages we will use
	int mem_avail = 0; // We could allocate new memory region or not?

	/* First we must check if the amount of free memory in
	 * virtual address space and physical address space is
	 * large enough to represent the amount of required 
	 * memory. If so, set 1 to [mem_avail].
	 * Hint: check [proc] bit in each page of _mem_stat
	 * to know whether this page has been used by a process.
	 * For virtual memory space, check bp (break pointer).
	 * */
	
	uint32_t cr_num_pages = 0;
	for (int i = 0; i < NUM_PAGES ; i++) {
		if (_mem_stat[i].proc == 0) {
			cr_num_pages ++;
		}
	}
	if (cr_num_pages >= num_pages && proc -> bp + num_pages * PAGE_SIZE < NUM_PAGES * PAGE_SIZE ) mem_avail = 1;
	else ret_mem = 0;
	if (mem_avail) {
		/* We could allocate new memory region to the process */
		ret_mem = proc->bp;
		proc->bp += num_pages * PAGE_SIZE;
		/* Update status of physical pages which will be allocated
		 * to [proc] in _mem_stat. Tasks to do:
		 * 	- Update [proc], [index], and [next] field
		 * 	- Add entries to segment table page tables of [proc]
		 * 	  to ensure accesses to allocated memory slot is
		 * 	  valid. */
		int32_t num_pages_use = 0;
        for (int i = 0, j = 0, k = 0; i < NUM_PAGES; i++)
        {
            if (_mem_stat[i].proc == 0)
            {
                _mem_stat[i].proc = proc->pid;
                _mem_stat[i].index = j;
                if (j != 0)
                    _mem_stat[k].next = i;
                /*------------------------*/
                addr_t physical_addr = i << OFFSET_LEN;
                addr_t first_lv = get_first_lv(ret_mem + j * PAGE_SIZE);
                addr_t second_lv = get_second_lv(ret_mem + j * PAGE_SIZE);
                // addr_t offset = get_offset(ret_mem + j * PAGE_SIZE);
                int booler = 0;
                /*Neu da co first index trong page table*/
                for (int n = 0; n < proc->seg_table->size; n++)
                {
                    if (proc->seg_table->table[n].v_index == first_lv)
                    {
                        proc->seg_table->table[n].pages->table[proc->seg_table->table[n].pages->size].v_index = second_lv;
                        proc->seg_table->table[n].pages->table[proc->seg_table->table[n].pages->size].p_index = physical_addr >> OFFSET_LEN;
                        proc->seg_table->table[n].pages->size++;
                        booler = 1;
                        break;
                    }
                }
                /*Neu chua co first index trong seg table tao page table moi*/
                if (booler == 0)
                {
                    int n = proc->seg_table->size;
                    proc->seg_table->size++;
                    proc->seg_table->table[n].pages = (struct page_table_t *)malloc(sizeof(struct page_table_t));
                    proc->seg_table->table[n].pages->size++;
                    proc->seg_table->table[n].v_index = first_lv;
                    proc->seg_table->table[n].pages->table[0].v_index = second_lv;
                    proc->seg_table->table[n].pages->table[0].p_index = physical_addr >> OFFSET_LEN;
                }
                /*------------------------*/
                k = i;
                j++;
                num_pages_use++;
                if (num_pages_use == num_pages)
                {
                    _mem_stat[k].next = -1;
                    break;
                }
            }
        }
	}
	pthread_mutex_unlock(&mem_lock);
	return ret_mem;
}


int free_mem(addr_t address, struct pcb_t *proc)
{

    /*TODO: Release memory region allocated by [proc]. The first byte of
    * this region is indicated by [address]. Task to do:
    *    - Set flag [proc] of physical page use by the memory block
    *      back to zero to indicate that it is free.
    *    - Remove unused entries in segment table and page tables of
    *      the process [proc].
    *    - Remember to use lock to protect the memory from other
    *      processes.  */
    pthread_mutex_lock(&mem_lock);
    addr_t physical_addr;
    if (translate(address, &physical_addr, proc)) // find physical address
    {
        int next = -1;
        int i = 0;
        for (; i < NUM_PAGES; i++)
        {
            if (physical_addr == i << OFFSET_LEN)
            {
                break;
            }
        }
        next = i;
	int del_pages = 0;
	addr_t v_address;
	struct trans_table_t * page_tbl;
        while (next != -1) // delete pages
        {
            _mem_stat[next].proc = 0;
            next = _mem_stat[next].next; // next page index
            v_address = address + del_pages * PAGE_SIZE;
            addr_t first_lv = get_first_lv(v_address); // segment
            addr_t second_lv = get_second_lv(v_address); // page
            for (int n = 0; n < proc->seg_table->size; n++) // finding segment
            {
                if (proc->seg_table->table[n].v_index == first_lv)
                {
                    page_tbl = proc->seg_table->table[n].pages;
                    for (int m = 0; m < page_tbl->size; m++)
                    {
                        if (page_tbl->table[m].v_index == second_lv)
                        {
                            // xoa page
                            int k = 0;
			     del_pages++;
                            for (k = m; k < page_tbl->size - 1; k++) 
                            {
                                page_tbl->table[k].v_index = page_tbl->table[k + 1].v_index;
                                page_tbl->table[k].p_index = page_tbl->table[k + 1].p_index;
                            }
                            
                            page_tbl->table[k].v_index = 0;
                            page_tbl->table[k].p_index = 0;
                            page_tbl->size--;
                            break;
                        }
                    }
                    if (page_tbl->size == 0)//xoa segment khi size = 0
                    {
                        free(page_tbl);
                        int m = 0;
                        //tinh tien phan tu trong page_table 
                        for (m = n; m < proc->seg_table->size - 1; m++)
                        {
                            proc->seg_table->table[m].v_index =
                            	proc->seg_table->table[m + 1].v_index;
                            proc->seg_table->table[m].pages =
                            	proc->seg_table->table[m + 1].pages;
                        }
                        proc->seg_table->table[m].v_index = 0;
                        proc->seg_table->table[m].pages = NULL;
                        proc->seg_table->size--;
                    }
                    break;
                }
            }
        }
    	proc->bp -= del_pages*PAGE_SIZE; // cap nhat break point
    }
    pthread_mutex_unlock(&mem_lock);
    return 0;
}


int read_mem(addr_t address, struct pcb_t * proc, BYTE * data) {
	addr_t physical_addr;
	if (translate(address, &physical_addr, proc)) {
		*data = _ram[physical_addr];
		return 0;
	}else{
		return 1;
	}
}

int write_mem(addr_t address, struct pcb_t * proc, BYTE data) {
	addr_t physical_addr;
	if (translate(address, &physical_addr, proc)) {
		_ram[physical_addr] = data;
		return 0;
	}else{
		return 1;
	}
}

void dump(void) {
	int i;
	for (i = 0; i < NUM_PAGES; i++) {
		if (_mem_stat[i].proc != 0) {
			printf("%03d: ", i);
			printf("%05x-%05x - PID: %02d (idx %03d, nxt: %03d)\n",
				i << OFFSET_LEN,
				((i + 1) << OFFSET_LEN) - 1,
				_mem_stat[i].proc,
				_mem_stat[i].index,
				_mem_stat[i].next
			);
			int j;
			for (	j = i << OFFSET_LEN;
				j < ((i+1) << OFFSET_LEN) - 1;
				j++) {
				
				if (_ram[j] != 0) {
					printf("\t%05x: %02x\n", j, _ram[j]);
				}
					
			}
		}
	}
}


