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
#include "./allocator_interface.h"
#include "./memlib.h"

// Don't call libc malloc!
#define malloc(...) (USE_MY_MALLOC)
#define free(...) (USE_MY_FREE)
#define realloc(...) (USE_MY_REALLOC)
#define DEBUG_CODE

// All blocks must have a specified minimum alignment.
// The alignment requirement (from config.h) is >= 8 bytes.
#ifndef ALIGNMENT
  #define ALIGNMENT 8
#endif

// Rounds up to the nearest multiple of ALIGNMENT.
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))

// The smallest aligned size that will hold a size_t value.
#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))

#define PTR_SIZE (ALIGN(sizeof(char *)))

// Minimum space that should be present for the block to split
#define MINIMUM_SPACE (SIZE_T_SIZE + PTR_SIZE + PTR_SIZE + SIZE_T_SIZE)

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

// Free ptr variable
static void* free_ptr = NULL;

void test_my_malloc();
void change_prev_next_values(void* block, void* change_next, void* change_prev);
void* construct_free_block(size_t size);

// init - Initialize the malloc package.  Called once before any other
// calls are made.  Since this is a very simple implementation, we just
// return success.
int my_init() {
  /*unsigned int initial_memory = 20000;*/
  /*void* initial_block = mem_sbrk(initial_memory);*/
  /*if(initial_block == (void*) - 1) {*/
  /*  return -1;*/
  /*}*/
  /**/
  /*free_ptr = initial_block;*/

#ifdef DEBUG_CODE
  test_my_malloc();
#endif

  return 0;
}

void*
construct_free_block(size_t size) {

    size_t aligned_size = ALIGN(size);

    size_t total_space = SIZE_T_SIZE + PTR_SIZE + PTR_SIZE + aligned_size + SIZE_T_SIZE;

    void* block = mem_sbrk(total_space);
    if(block == (void*) - 1){
        return (void*) - 1;
    }

    size_t* block_header = (size_t*)block;
    size_t* block_footer = (size_t*)((char*)block + SIZE_T_SIZE + PTR_SIZE + PTR_SIZE + aligned_size);

    *block_header = aligned_size;
    *block_footer = aligned_size;

    return block;
}

void
change_prev_next_values(void* block, void* change_next, void* change_prev){

    void** next_ptr = (void**)((char*)block + SIZE_T_SIZE);
    void** prev_ptr = (void**)((char*)block + SIZE_T_SIZE + PTR_SIZE);

    void* final_next = change_next ? (void*)((char*)change_next + SIZE_T_SIZE) : NULL;
    void* final_prev = change_prev ? (void*)((char*)change_prev + SIZE_T_SIZE) : NULL;

    *next_ptr = final_next;
    *prev_ptr = final_prev;
}

void
traversing(void* free_ptr){

    void* current = free_ptr;

    while(current != NULL){
        size_t* header_size = (size_t*)((char*)current - SIZE_T_SIZE);
        size_t size = *header_size;
        size_t* footer_size = (size_t*)((char*)current + PTR_SIZE + PTR_SIZE + size);

        printf("Block: %zu\n", size);

        current = *(void**)current;
    }
}

void
test_my_malloc() {
    void* block1 = construct_free_block(1024);
    void* block2 = construct_free_block(2048);
    void* block3 = construct_free_block(4096);

    change_prev_next_values(block1, block2, NULL);
    change_prev_next_values(block2, block3, block1);
    change_prev_next_values(block3, NULL, block2);

    free_ptr = (void*)((char*)block1 + SIZE_T_SIZE);

    traversing(free_ptr);

    printf("Testing Complete :)\n");
}

void* traverse_free_list(void** free_ptr, size_t requested_size){

    // Creating a copy of free pointer so as to not lose it
    void* current = *free_ptr;

    // next_ptr_prev_block points to previous block inside the free list compared
    // to the current position
    // HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH
    void* next_ptr_prev_block = NULL;

    while(current != NULL){
        
        // Not technically a next block but helps in saving current
        // in a different form; so it is easier to dereference it, later on
        void** next_ptr_current_block = (void**)current;

        // Casting the void pointer to size_t pointer;
        size_t* size_block = (size_t*)((char*)current - SIZE_T_SIZE);
        //Block looks like: SIZE + PTR + SPACE + SIZE

        // Getting the actual size from the pointer by derefrecing it
        size_t actual_size = *size_block;

        if(actual_size + PTR_SIZE + PTR_SIZE >= requested_size){

            // Getting the prev_ptr of the next block
            void** prev_ptr_next_block = (void**)((char*)(*next_ptr_current_block) + PTR_SIZE);

            // If we find appropriate block at the very first position itself
            // We just move the free pointer to the next block
            // So now free list starts from second block instead of first block
            if(next_ptr_prev_block == NULL){
                *free_ptr = *next_ptr_current_block;

                // Making the prev_ptr to point to NULL
                *prev_ptr_next_block = NULL;
            }

            // Skipping the chosen block and making the next_ptr_prev_block point to next block
            else{
                *(void**)next_ptr_prev_block = *next_ptr_current_block;

                // If appropriate block is middle one
                if(*next_ptr_current_block != NULL){

                    void** prev_ptr_current_block = (void**)((char*)current + PTR_SIZE);

                    *prev_ptr_next_block = *prev_ptr_current_block;
                }
            }

            return current;
        }

        // next_ptr_prev_block value is changed to current block
        next_ptr_prev_block = current;

        // Moving current to the next block
        current = *next_ptr_current_block;
    }

    return (void*) - 1;
}

void* my_malloc(size_t size) {

    // Aligning the size to 8
    size_t aligned_size = ALIGN(size);

    // Iterating free list and getting the pointer to the block if sizes matched
    void* free_list_output = traverse_free_list(&free_ptr, aligned_size);

    // No ideal block found
    if(free_list_output == (void*) - 1){

        // Calling mem_sbrk for new memory block because we didnt find
        // one with appropriate size in the free list
        // The 2 SIZE_T_SIZE are added because we want them even if it is a 
        // allocated block
        // The additional PTR_SIZE is to accomodate the new prev_ptr
        // for doubly linked list
        void* new_block = mem_sbrk(aligned_size + SIZE_T_SIZE + SIZE_T_SIZE + PTR_SIZE);

        // Set the size value at header and "+1" to denote allocated block
        *((size_t*)new_block) = aligned_size + PTR_SIZE + 1;

        // Getting the pointer to the footer size
        size_t* footer_new_block = (size_t*)((char*)new_block + SIZE_T_SIZE + aligned_size + PTR_SIZE);

        // Set the size value at footer and "+1" to denote allocated block
        *footer_new_block = aligned_size + PTR_SIZE + 1;

        // Casting the new block to char* and moving it ahead by SIZE_T
        // because the allocation should start from the actual space
        // which starts after size_t
        // Allocated Memory block looks like: SIZE + ALIGNED SPACE + SIZE
        return (void*)((char*)new_block + SIZE_T_SIZE);
    }

    // Fetching the pointer to the size_t value of the block
    size_t* header_size_ptr = (size_t*)((char*)free_list_output - SIZE_T_SIZE);

    // Actual block size
    size_t actual_block_size = *header_size_ptr;

    // Getting the pointer to footer
    // Here we are thinking only for the block that is to be allocated
    // hence only moving ahead by ptr_size + ptr_size + aligned_size
    // and not caring about the free space if present
    size_t* footer_size_ptr = (size_t*)((char*)free_list_output + PTR_SIZE + PTR_SIZE + aligned_size);

    // Here we check if the space left is greater than or equal to 32
    // If it is then we can treat the rest of space as a new free block
    // Thereby reducing internal fragmentation
    size_t size_difference = actual_block_size - aligned_size;

    if(size_difference >= MINIMUM_SPACE){

        size_t* header_allocated = (size_t*)((char*)free_list_output - SIZE_T_SIZE);

        size_t* footer_allocated = (size_t*)((char*)free_list_output + PTR_SIZE + PTR_SIZE + aligned_size);

        *header_allocated = (aligned_size + PTR_SIZE + 1);
        *footer_allocated = (aligned_size + PTR_SIZE + 1);

        // BLOCK looks like size + ptr + ptr + space + size
        // So the total space that can be utilized by a process is space + PTR_SIZE + PTR_SIZE
        // out of which aligned_size will be used
        size_t block_space = actual_block_size + PTR_SIZE + PTR_SIZE - aligned_size;

        // split_block pointer points to the start of the new free block
        void* split_block = (void*)((char*)free_list_output + PTR_SIZE + PTR_SIZE + aligned_size + SIZE_T_SIZE);

        // Subtracting the space of 2 size_t values and 1 free_ptr for the new block
        size_t real_block_space = block_space - SIZE_T_SIZE - SIZE_T_SIZE - PTR_SIZE - PTR_SIZE;

        size_t* header_split_block = (size_t*)split_block;
        size_t* footer_split_block = (size_t*)((char*)split_block + SIZE_T_SIZE + PTR_SIZE + PTR_SIZE + real_block_space);

        (*header_split_block) = real_block_space;
        (*footer_split_block) = real_block_space;

        void** first_block_prev_ptr = (void**)((char*)free_ptr + PTR_SIZE);

        void** split_block_prev_ptr = (void**)((char*)split_block + PTR_SIZE + PTR_SIZE);
        
        *first_block_prev_ptr = *split_block_prev_ptr;

        // Getting the pointer to the split block
        void** split_block_next_ptr = (void**)((char*)split_block + SIZE_T_SIZE);

        // Making it so that split block points to the start of free list
        *split_block_next_ptr = free_ptr;

        // Split block becomes the first free block in free list
        free_ptr = split_block_next_ptr;
    }
    else{

        // Adding PTR_SIZE + PTR_SIZE because the allocated block doesnt need the
        // extra next_ptr and prev_ptr space
        // Adding 1 because that signifies that the block is allocated because all the sizes are
        // supposed to be multiples of 8 thereby being even
        // So odd size denotes allocated block
        // Why did i do this? Because i think it will help during the coalescing stage
        (*header_size_ptr) += (PTR_SIZE + PTR_SIZE + 1);
        (*footer_size_ptr) += (PTR_SIZE + PTR_SIZE + 1);

    }

    return free_list_output;
}

// free - Freeing a block does nothing.
void my_free(void* ptr) {
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
