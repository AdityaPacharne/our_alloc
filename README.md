# our_alloc (Our Memory Allocator)
`our_alloc` is a custom dynamic memory allocator implementation in C  
Named as a pun on Low Level Learning's "my_alloc" video, but built from scratch.

Just a final year student trying to understand how malloc really works under the hood.

---

## Development Process
I documented the entire development process on my [YouTube channel](https://youtube.com/@engineer_for_fun). Each video is ~1 hour of real coding (no LLM assistance, all mistakes included). If you want to see someone struggle through memory allocator bugs in real-time, check it out.

---

## What it does
- **malloc** - allocates memory blocks with 8-byte alignment
- **free** - deallocates memory and immediately coalesces adjacent free blocks
- **realloc** - (currently broken on another branch, main branch is working, working on fixing some overwrite bugs)
- Uses a **doubly linked free list** for O(1) insertion/removal of free blocks.
- **Boundary Tags** enable O(1) coalescing with adjacent free blocks.
- **First-fit** search strategy with block splitting
- Coalesces free blocks on both `free()` and `realloc()` calls

---

## Performance
Current score: **80.4** (changing as I tune realloc)
- **90% throughput**
- **71% memory utilization**
- Baseline score: **30.5** (naive bump allocator that doesn't even free)

The baseline just moves the brk pointer on malloc, does nothing on free, and realloc always calls malloc+free even when shrinking. So yeah, we're doing *slightly* better than that.

---

## Implementation Details

### Memory Layout
```
[HEADER: 24 bytes] [payload...] [FOOTER: 8 bytes]
```

**Header structure:**
```c
typedef struct header_block {
    size_t size;
    struct header_block* next;
    struct header_block* prev;
} header_block;
```

**Footer structure:**
```c
typedef struct footer_block {
    size_t size;
} footer_block;
```

Total overhead: **32 bytes per block**

### Key Features
- **Immediate coalescing**: When a block is freed, it immediately coalesces with adjacent free blocks (if any)
- **First-fit allocation**: Searches free list from the beginning for the first block that fits
- **Block splitting**: If remaining space after allocation is ≥ 32 bytes (min block size), split it into a new free block
- **Boundary tag coalescing**: Can coalesce in O(1) time by checking headers and footers of adjacent blocks

---

## What I learned building this

### Big "aha!" moments:
1. **Reading the [dlmalloc documentation](https://gee.cs.oswego.edu/dl/html/malloc.html)** - This is where I finally understood proper coalescing. Added heap start/end boundary checks to avoid coalescing out-of-bounds memory.

2. **LLDB debugger** - Game changer. Debugging memory allocators without a debugger is pain. With LLDB? Actually manageable.

3. **Why realloc is hard** - Currently debugging issues where realloc overwrites other blocks, leading to impossible results like 1500% utilization (which is... not supposed to happen since max is 100%). This is what I'm fixing now.

---

## Project Context
This is a project from **MIT 6.172: Performance Engineering of Software Systems**

**Rules:**
- Only allowed to modify `allocator.c`
- Must implement malloc, free, and realloc using only the provided `mem_sbrk()` function

---

## How to build and test
```bash
make && ./mdriver
```

That's it. The benchmarking harness tests throughput, utilization, and correctness.

---

## Current Status
malloc - working  
free - working  
coalescing - working  
splitting - working  
realloc - in progress (has bugs, working on fixes)

---

## License
Copyright (c) 2015 MIT License by 6.172 Staff

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to
deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
IN THE SOFTWARE.

---
