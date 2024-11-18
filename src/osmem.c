// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include <unistd.h>
#include <sys/mman.h>
#include "block_meta.h"

#define MMAP_THRESHOLD (128 * 1024) //128 KB
#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))
#define BLOCK_META_SIZE 32 //aligned size of struct block_meta


struct block_meta *head_block;
size_t threshold = MMAP_THRESHOLD;

void merge_free_blocks(void)
{
	struct block_meta *temp = head_block;
	char merged;

	while (1) {
		merged = 0;
		if (temp->status == STATUS_FREE) {
			if (temp->next) {
				struct block_meta *next_block = temp->next;

				if (next_block->status == STATUS_FREE) {
					if (next_block->next) {
						next_block->next->prev = temp;
						temp->next = next_block->next;
					} else {
						temp->next = NULL;
					}
					temp->size = temp->size + next_block->size + BLOCK_META_SIZE;
					temp->status = STATUS_FREE;
					merged = 1;
				}
			} else {
				break;
			}
		}
		if (!merged) {
			if (temp->next)
				temp = temp->next;
			else
				break;
		}
	}
}

struct block_meta *find_best_block(size_t size)
{
	merge_free_blocks();
	struct block_meta *temp = head_block;
	struct block_meta *best_block = NULL;
	size_t min_diff = __UINT64_MAX__;

	if (head_block->size >= size && head_block->status == STATUS_FREE) {
		best_block = head_block;
		min_diff = head_block->size - size;
	}

	while (1) {
		if (temp->status == STATUS_FREE)
			if (temp->size >= size && temp->size - size < min_diff) {
				best_block = temp;
				min_diff = temp->size - size;
			}
		if (temp->next)
			temp = temp->next;
		else
			break;
	}

	if (best_block)
		return best_block;
	return NULL;
}

struct block_meta *get_last_block(void)
{
	if (!head_block)
		return NULL;

	struct block_meta *temp = head_block;

	while (temp->next)
		temp = temp->next;
	return temp;
}

void add_to_block_list(struct block_meta *block)
{
	if (head_block == NULL)
		return;

	struct block_meta *last_block = get_last_block();

	last_block->next = block;
	block->prev = last_block;
	block->next = NULL;
}

void remove_block_from_list(struct block_meta *block)
{
	block->prev->next = block->next;
	block->next->prev = block->prev;
}

void copy_data(void *dest, void *src, size_t size)
{
	for (size_t i = 0; i < size; i++)
		*(char *)(dest + i) = *(char *)(src + i);
}

void split_block(struct block_meta *block, size_t size)
{
	if (block->size - size < BLOCK_META_SIZE + 8)
		return;

	struct block_meta *remaining_block = (void *)block + BLOCK_META_SIZE + size;

	remaining_block->size = block->size - size - BLOCK_META_SIZE;
	remaining_block->status = STATUS_FREE;
	block->size = size;

	if (block->next) {
		remaining_block->next = block->next;
		block->next->prev = remaining_block;
	} else {
		remaining_block->next = NULL;
	}

	block->next = remaining_block;
	remaining_block->prev = block;
}

void *os_malloc(size_t size)
{
	if (size == 0)
		return NULL;

	if (size <= threshold - BLOCK_META_SIZE) {
		if (!head_block) {
			void *heap_start = sbrk(0);

			DIE(heap_start == NULL, "brk failed");
			int ret = brk(heap_start + MMAP_THRESHOLD);

			DIE(ret == -1, "brk failed");

			struct block_meta *prealloc_block = heap_start;

			prealloc_block->next = NULL;
			prealloc_block->prev = NULL;
			prealloc_block->size = MMAP_THRESHOLD - BLOCK_META_SIZE;
			prealloc_block->status = STATUS_FREE;
			head_block = prealloc_block;
		}

		struct block_meta *best_block = find_best_block(ALIGN(size));

		if (best_block) {
			split_block(best_block, ALIGN(size));
			best_block->status = STATUS_ALLOC;
		} else {
			best_block = get_last_block();

			if (best_block->status == STATUS_FREE) {
				size_t size_diff = ALIGN(size) - best_block->size;
				void *ret = sbrk(size_diff);

				DIE(ret == NULL, "brk failed");

				best_block->size += size_diff;
				best_block->status = STATUS_ALLOC;
			} else {
				best_block = sbrk(BLOCK_META_SIZE + ALIGN(size));
				DIE(best_block == NULL, "brk failed");

				best_block->size = ALIGN(size);
				best_block->status = STATUS_ALLOC;
				add_to_block_list(best_block);
			}
		}
		return (void *)best_block + BLOCK_META_SIZE;
	}
	void *ret = mmap(NULL, ALIGN(size) + BLOCK_META_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);

	DIE(ret == MAP_FAILED, "mmap failed");

	struct block_meta *new_block = ret;

	new_block->size = ALIGN(size);
	new_block->status = STATUS_MAPPED;

	return (void *)new_block + BLOCK_META_SIZE;
}

void os_free(void *ptr)
{
	if (ptr == NULL)
		return;

	struct block_meta *block = ptr - BLOCK_META_SIZE;

	if (block == NULL)
		return;

	if (block->status == STATUS_FREE)
		return;

	if (block->status == STATUS_ALLOC) {
		block->status = STATUS_FREE;
		return;
	}

	int ret = munmap(block, block->size + BLOCK_META_SIZE);

	DIE(ret == -1, "free failed");
}

void *os_calloc(size_t nmemb, size_t size)
{
	if (nmemb * size == 0)
		return NULL;

	threshold = getpagesize();
	void *start = os_malloc(nmemb * size);

	threshold = MMAP_THRESHOLD;

	for (size_t i = 0; i < nmemb * size; i++)
		*(char *)(start + i) = 0;
	return start;
}

void *os_realloc(void *ptr, size_t size)
{
	if (ptr == NULL)
		return os_malloc(size);

	if (size == 0) {
		os_free(ptr);
		return NULL;
	}

	struct block_meta *block = ptr - BLOCK_META_SIZE;

	if (block->status == STATUS_FREE)
		return NULL;

	if (block->status == STATUS_MAPPED || ALIGN(size) > MMAP_THRESHOLD) {
		void *old_data = (void *)block + BLOCK_META_SIZE;
		void *new_data = os_malloc(size);
		size_t min_size = ALIGN(size) < block->size ? ALIGN(size) : block->size;

		copy_data(new_data, old_data, min_size);
		os_free(old_data);
		return (void *)new_data;
	}

	if (block->size == ALIGN(size)) {
		return ptr;
	} else if (block->size > ALIGN(size)) {
		split_block(block, ALIGN(size));
		return (void *)block + BLOCK_META_SIZE;
	}

	if (!block->next) {
		size_t size_diff = ALIGN(size) - block->size;
		void *ret = sbrk(size_diff);

		DIE(ret == NULL, "brk failed");
		block->size = ALIGN(size);
		return (void *)block + BLOCK_META_SIZE;
	}

	while (1) {
		if (block->next) {
			struct block_meta *next_block = block->next;

			if (next_block->status == STATUS_FREE) {
				if (next_block->next) {
					block->next = next_block->next;
					next_block->next->prev = block;
				} else {
					block->next = NULL;
				}
				block->size += BLOCK_META_SIZE + next_block->size;
			} else {
				break;
			}
		} else {
			break;
		}
		if (block->size >= ALIGN(size))
			break;
	}

	if (block->size >= ALIGN(size)) {
		split_block(block, ALIGN(size));
		return (void *)block + BLOCK_META_SIZE;
	}

	void *old_data = (void *)block + BLOCK_META_SIZE;
	void *new_data = os_malloc(size);
	size_t min_size = ALIGN(size) < block->size ? ALIGN(size) : block->size;

	copy_data(new_data, old_data, min_size);
	os_free((void *)old_data);
	return (void *)new_data;
}
