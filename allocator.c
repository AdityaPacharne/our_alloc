/**
 * Copyright (c) 2015 MIT License by 6.172 Staff
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 **/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include "./allocator_interface.h"
#include "./memlib.h"

// Don't call libc malloc!
#define malloc(...) (USE_MY_MALLOC)
#define free(...) (USE_MY_FREE)
#define realloc(...) (USE_MY_REALLOC)
/*#define DEBUG_CODE*/

// All blocks must have a specified minimum alignment.
// The alignment requirement (from config.h) is >= 8 bytes.
#ifndef ALIGNMENT
  #define ALIGNMENT 8
#endif

// Rounds up to the nearest multiple of ALIGNMENT.
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))

// The smallest aligned size that will hold a size_t value.
#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))

// check - This checks our invariant that the size_t header before every
// block points to either the beginning of the next block, or the end of the
// heap.
int my_check() {
  char* p;
  char* lo = (char*)mem_heap_lo();
  char* hi = (char*)mem_heap_hi() + 1;
  size_t size = 0;

  p = lo;
  while (lo <= p && p < hi) {
    size = ALIGN(*(size_t*)p + SIZE_T_SIZE);
    p += size;
  }

  if (p != hi) {
    printf("Bad headers did not end at heap_hi!\n");
    printf("heap_lo: %p, heap_hi: %p, size: %lu, p: %p\n", lo, hi, size, p);
    return -1;
  }

  return 0;
}

typedef struct header_block {
    size_t size;
    struct header_block* next;
    struct header_block* prev;
} header_block;

typedef struct footer_block {
    size_t size;
} footer_block;

#define HEADER sizeof(header_block)
#define FOOTER sizeof(footer_block)

static header_block* free_ptr = NULL;

void test_my_malloc();
void change_prev_next_values(header_block* block, header_block* change_next, header_block* change_prev);
header_block* construct_free_block(size_t size);

// init - Initialize the malloc package.  Called once before any other
// calls are made.  Since this is a very simple implementation, we just
// return success.
int my_init() {

    free_ptr = NULL;

#ifdef DEBUG_CODE
    test_my_malloc();
#endif

    return 0;
}

header_block*
construct_free_block(size_t size) {
    
    size_t aligned_size = ALIGN(size);
    size_t total_space = aligned_size + HEADER + FOOTER;

    void* block = mem_sbrk(total_space);
    if(block == (void*) - 1){
        return (void*) - 1;
    }

    header_block* header = (header_block*)block;
    footer_block* footer = (footer_block*)((char*)block + HEADER + aligned_size);

    header->size = aligned_size;
    footer->size = aligned_size;

    return header;
}

void
change_prev_next_values(header_block* block, header_block* change_next, header_block* change_prev){
    block->next = change_next;
    block->prev = change_prev;
}

void
traversing(header_block* free_ptr){

    header_block* current = free_ptr;
    while(current != NULL){
        printf("%zu -> ", current->size);
        current = current->next;
    }
    printf("\n");
}

void
test_my_malloc() {
    printf("\n\n");
    header_block* block1 = construct_free_block(1024);
    header_block* block2 = construct_free_block(2048);
    header_block* block3 = construct_free_block(4096);

    change_prev_next_values(block1, block2, NULL);
    change_prev_next_values(block2, block3, block1);
    change_prev_next_values(block3, NULL, block2);

    traversing(block1);

    printf("Testing Complete :)\n\n\n");
}

header_block*
traverse_free_list(header_block** free_ptr, size_t requested_size){

    header_block* current = *free_ptr;

    while(current != NULL){

        /*sleep(2);*/

        if(current->size >= requested_size){
            if(current->prev == NULL){
                (*free_ptr) = current->next;
                if(current->next != NULL){
                    current->next->prev = NULL;
                }
            }
            else{
                current->prev->next = current->next;
                if(current->next != NULL){
                    current->next->prev = current->prev;
                }
            }
            current->next = NULL;
            current->prev = NULL;
            return current;
        }
        current = current->next;
    }
    return NULL;
}

void*
my_malloc(size_t size){

    size_t aligned_size = ALIGN(size);

    header_block* free_block = traverse_free_list(&free_ptr, aligned_size);

    if(free_block == NULL){

        void* new_block = mem_sbrk(HEADER + aligned_size + FOOTER);

        if(new_block == (void*) - 1){
            return (void*) - 1;
        }

        header_block* new_header = (header_block*)new_block;
        footer_block* new_footer = (footer_block*)((char*)new_block + HEADER + aligned_size);

        new_header->size = (aligned_size + 1);
        new_footer->size = (aligned_size + 1);

        void* space = (void*)((char*)new_block + HEADER);

        return space;
    }

    size_t block_size = free_block->size;

    if(block_size - aligned_size >= HEADER + FOOTER){

        size_t total_split = block_size - aligned_size;
        size_t useful_space = total_split - HEADER - FOOTER;

        header_block* allocated_header = (header_block*)free_block;
        footer_block* allocated_footer = (footer_block*)((char*)free_block + HEADER + aligned_size);

        allocated_header->size = aligned_size + 1;
        allocated_header->next = NULL;
        allocated_header->prev = NULL;

        allocated_footer->size = aligned_size + 1;

        header_block* split_header = (header_block*)((char*)allocated_footer + FOOTER);
        footer_block* split_footer = (footer_block*)((char*)split_header + HEADER + useful_space);

        split_header->size = useful_space;
        split_footer->size = useful_space;

        split_header->next = free_ptr;
        split_header->prev = NULL;

        if(free_ptr != NULL){
            free_ptr->prev = split_header;
        }

        free_ptr = split_header;

        void* allocated_space = (void*)((char*)allocated_header + HEADER);

        return allocated_space;
    }
    else{
        header_block* header = free_block;
        footer_block* footer = (footer_block*)((char*)header + HEADER + header->size);

        (header->size)++;
        (footer->size)++;

        void* space = (void*)((char*)free_block + HEADER);

        return space;
    }
}

bool
left_free_block(void* ptr) {

    footer_block* left_block = (footer_block*)((char*)ptr - HEADER - FOOTER);

    if ((void*)left_block < mem_heap_lo()) return false;

    size_t left_block_size = left_block->size;

    if(left_block_size && (left_block_size % 2) == 0) return true;
    return false;
}

bool
right_free_block(void* ptr) {

    header_block* current = (header_block*)((char*)ptr - HEADER);
    size_t block_size = current->size - 1;
    header_block* right_block = (header_block*)((char*)ptr + block_size + FOOTER);

    if ((void*)right_block > mem_heap_hi()) return false;

    size_t right_block_size = right_block->size;

    if(right_block_size && right_block_size % 2 == 0) return true;
    return false;
}

void
skip_block(header_block* block, header_block** free_ptr){

    if(block->prev == NULL){
        (*free_ptr) = block->next;
    }
    else if(block->prev != NULL){
        block->prev->next = block->next;
    }
    if(block->next != NULL){
        block->next->prev = block->prev;
    }
    block->next = NULL;
    block->prev = NULL;
}

header_block*
coalescing_rl(header_block** free_ptr, void* ptr){

    header_block* block = (header_block*)((char*)ptr - HEADER);
    size_t block_size = block->size - 1;

    footer_block* left_block_footer = (footer_block*)((char*)ptr - HEADER - FOOTER);
    header_block* left_block = (header_block*)((char*)left_block_footer - left_block_footer->size - HEADER);

    header_block* right_block = (header_block*)((char*)ptr + block_size + FOOTER);
    footer_block* right_block_footer = (footer_block*)((char*)right_block + HEADER + right_block->size);

    size_t total_new_size = block_size + left_block->size + right_block->size + (2 * HEADER) + (2 * FOOTER);

    skip_block(left_block, free_ptr);
    skip_block(right_block, free_ptr);

    left_block->size = total_new_size;
    right_block_footer->size = total_new_size;

    header_block* new_block = left_block;

    return new_block;
}

header_block*
coalescing_l(header_block** free_ptr, void* ptr){

    header_block* block = (header_block*)((char*)ptr - HEADER);
    size_t block_size = block->size - 1;

    footer_block* block_footer = (footer_block*)((char*)ptr + block_size);

    footer_block* left_block_footer = (footer_block*)((char*)ptr - HEADER - FOOTER);
    header_block* left_block = (header_block*)((char*)left_block_footer - left_block_footer->size - HEADER);

    size_t total_new_size = block_size + left_block->size + HEADER + FOOTER;

    skip_block(left_block, free_ptr);

    left_block->size = total_new_size;
    block_footer->size = total_new_size;

    header_block* new_block = left_block;

    return new_block;
}

header_block*
coalescing_r(header_block** free_ptr, void* ptr){

    header_block* block = (header_block*)((char*)ptr - HEADER);
    size_t block_size = block->size - 1;

    header_block* right_block = (header_block*)((char*)ptr + block_size + FOOTER);
    footer_block* right_block_footer = (footer_block*)((char*)right_block + HEADER + right_block->size);

    size_t total_new_size = block_size + right_block->size + HEADER + FOOTER;

    skip_block(right_block, free_ptr);

    block->size = total_new_size;
    right_block_footer->size = total_new_size;

    header_block* new_block = block;

    return new_block;
}

void
my_free(void* ptr) {

    bool left_free = left_free_block(ptr);
    bool right_free = right_free_block(ptr);

    header_block* new_block = (header_block*)((char*)ptr - HEADER);
    footer_block* new_block_footer = (footer_block*)((char*)ptr + (new_block->size - 1));

    if(left_free && right_free){
        new_block = coalescing_rl(&free_ptr, ptr);
    }
    else if(left_free){
        new_block = coalescing_l(&free_ptr, ptr);
    }
    else if(right_free){
        new_block = coalescing_r(&free_ptr, ptr);
    }
    else{
        (new_block->size)--;
        (new_block_footer->size)--;
    }

    new_block->next = free_ptr;

    header_block* next_block = free_ptr;
    free_ptr = new_block;

    new_block->prev = NULL;

    if(next_block != NULL){
        next_block->prev = new_block;
    }
}

void*
my_realloc(void* ptr, size_t size) {

    size_t aligned_size = ALIGN(size);

    header_block* block = (block_header*)ptr;
    size_t block_size = block->size & (~1);
    footer_block* block = (footer_block*)((char*)ptr + block_size);

    size_t difference = block_size - aligned_size;

    if(difference > 0 && difference >= HEADER + FOOTER){

        header_block* new_h = (header_block*)ptr;
        footer_block* new_f = (footer_block*)((char*)ptr + aligned_size);

        new_h->size = aligned_size | 1;
        new_f->size = aligned_size | 1;
        new_h->next = NULL;
        new_h->prev = NULL;

        size_t useful_space = difference - HEADER - FOOTER;

        header_block* split_h = (header_block*)((char*)new_f + FOOTER);
        footer_block* split_f = (footer_block*)((char*)split_h + useful_space);

        split_h->size = useful_space;
        split_f->size = useful_space;

        split_h->next = free_ptr;
        split_h->prev = NULL;
        if(free_ptr != NULL) free_ptr->prev = split_h;
        free_ptr = split_h;

    }
    else if(difference > 0){
        return ptr;
    }

    bool left_free = left_free_block(ptr);
    bool right_free = right_free_block(ptr);

}

// realloc - Implemented simply in terms of malloc and free
void* my_realloc(void* ptr, size_t size) {
  void* newptr;
  size_t copy_size;

  // Allocate a new chunk of memory, and fail if that allocation fails.
  newptr = my_malloc(size);
  if (NULL == newptr) {
    return NULL;
  }

  // Get the size of the old block of memory.  Take a peek at my_malloc(),
  // where we stashed this in the SIZE_T_SIZE bytes directly before the
  // address we returned.  Now we can back up by that many bytes and read
  // the size.
  copy_size = *(size_t*)((uint8_t*)ptr - SIZE_T_SIZE);

  // If the new block is smaller than the old one, we have to stop copying
  // early so that we don't write off the end of the new block of memory.
  if (size < copy_size) {
    copy_size = size;
  }

  // This is a standard library call that performs a simple memory copy.
  memcpy(newptr, ptr, copy_size);

  // Release the old block.
  my_free(ptr);

  // Return a pointer to the new block.
  return newptr;
}
