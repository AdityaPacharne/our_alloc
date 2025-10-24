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
#define MINIMUM_SPACE (SIZE_T_SIZE + PTR_SIZE + SIZE_T_SIZE)

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
  return 0;
}

void* traverse_free_list(void** free_ptr, size_t requested_size){

    // Creating a copy of free pointer so as to not lose it
    void* copy_free_ptr = *free_ptr;

    // prev_block points to previous block inside the free list compared
    // to the current position
    void* prev_block = NULL;

    while(copy_free_ptr != NULL){
        
        // Not technically a next block but helps in saving copy_free_ptr
        // in a different form; so it is easier to dereference it, later on
        void** next_block = (void**)copy_free_ptr;

        // Casting the void pointer to size_t pointer;
        size_t* size_block = (size_t*)((char*)copy_free_ptr - SIZE_T_SIZE);
        //Block looks like: SIZE + PTR + SPACE + SIZE

        // Getting the actual size from the pointer by derefrecing it
        size_t actual_size = *size_block;

        if(actual_size + PTR_SIZE >= requested_size){

            // If we find appropriate block at the very first position itself
            // We just move the free pointer to the next block
            // So now free list starts from second block instead of first block
            if(prev_block == NULL){
                *free_ptr = *next_block;
            }

            // Skipping the chosen block and making the prev_block point to next block
            else{
                *(void**)prev_block = *next_block;
            }

            return copy_free_ptr;
        }

        // prev_block value is changed to current block
        prev_block = copy_free_ptr;

        // Moving copy_free_ptr to the next block
        copy_free_ptr = *next_block;
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
        void* new_block = mem_sbrk(aligned_size + SIZE_T_SIZE + SIZE_T_SIZE);

        // Set the size value at header and "+1" to denote allocated block
        *((size_t*)new_block) = aligned_size + 1;

        // Getting the pointer to the footer size
        size_t* footer_new_block = (size_t*)((char*)new_block + SIZE_T_SIZE + aligned_size);

        // Set the size value at footer and "+1" to denote allocated block
        *footer_new_block = aligned_size + 1;

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
    // hence only moving ahead by ptr_size + aligned_size
    // and not caring about the free space if present
    size_t* footer_size_ptr = (size_t*)((char*)free_list_output + PTR_SIZE + aligned_size);

    // Here we check if the space left is greater than or equal to 24 
    // If it is then we can treat the rest of space as a new free block
    // Thereby reducing internal fragmentation
    size_t size_difference = actual_block_size - aligned_size;

    if(size_difference >= MINIMUM_SPACE){

        // BLOCK looks like size + ptr + space + size
        // So the total space that can be utilized by a process is space + PTR_SIZE
        // out of which aligned_size will be used
        size_t block_space = actual_block_size + PTR_SIZE - aligned_size;

        // split_block pointer points to the start of the new free block
        void* split_block = (void*)((char*)free_list_output + PTR_SIZE + aligned_size + SIZE_T_SIZE);

        // Subtracting the space of 2 size_t values and 1 free_ptr for the new block
        size_t real_block_space = block_space - SIZE_T_SIZE - SIZE_T_SIZE - PTR_SIZE;

        size_t* header_split_block = (size_t*)split_block;
        size_t* footer_split_block = (size_t*)((char*)split_block + SIZE_T_SIZE + PTR_SIZE + real_block_space);

        (*header_split_block) = real_block_space;
        (*footer_split_block) = real_block_space;

        // Getting the pointer to the split block
        void** split_block_ptr = (void**)((char*)split_block + SIZE_T_SIZE);

        // Making it so that split block points to the start of free list
        *split_block_ptr = free_ptr;

        // Split block becomes the first free block in free list
        free_ptr = split_block_ptr;
    }
    else{

        // Adding PTR_SIZE because the allocated block doesnt need the extra free pointer space
        // Adding 1 because that signifies that the block is allocated because all the sizes are
        // supposed to be multiples of 8 thereby being even
        // So odd size denotes allocated block
        // Why did i do this? Because i think it will help during the coalescing stage
        (*header_size_ptr) += (PTR_SIZE + 1);
        (*footer_size_ptr) += (PTR_SIZE + 1);

    }

    return free_list_output;
}

//  malloc - Allocate a block by incrementing the brk pointer.
//  Always allocate a block whose size is a multiple of the alignment.
void* my_malloc(size_t size) {
  // We allocate a little bit of extra memory so that we can store the
  // size of the block we've allocated.  Take a look at realloc to see
  // one example of a place where this can come in handy.
  int aligned_size = ALIGN(size + SIZE_T_SIZE);

  // Expands the heap by the given number of bytes and returns a pointer to
  // the newly-allocated area.  This is a slow call, so you will want to
  // make sure you don't wind up calling it on every malloc.
  void* p = mem_sbrk(aligned_size);

  if (p == (void*) - 1) {
    // Whoops, an error of some sort occurred.  We return NULL to let
    // the client code know that we weren't able to allocate memory.
    return NULL;
  } else {
    // We store the size of the block we've allocated in the first
    // SIZE_T_SIZE bytes.
    *(size_t*)p = size;

    // Then, we return a pointer to the rest of the block of memory,
    // which is at least size bytes long.  We have to cast to uint8_t
    // before we try any pointer arithmetic because voids have no size
    // and so the compiler doesn't know how far to move the pointer.
    // Since a uint8_t is always one byte, adding SIZE_T_SIZE after
    // casting advances the pointer by SIZE_T_SIZE bytes.
    return (void*)((char*)p + SIZE_T_SIZE);
  }
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
