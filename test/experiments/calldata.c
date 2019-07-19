#include <sys/mman.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <stdint.h>

#define printf(...)

void print_hex(const char *s)
{
    while (*s)
        printf("%02x", (unsigned int)(unsigned char)*s++);
    printf("\n");
}

typedef struct state
{
    int stack_size;
    int stack[100];
} state;

typedef void (*op_fn)(state *);

const char* noop_code = "\xc3";

void add(state* s)
{
    printf("add(%d)\n", s->stack_size);
    --s->stack_size;
    s->stack[s->stack_size - 1] += s->stack[s->stack_size];
}

void dispatch(state *s, op_fn op)
{
    op(s);
    op(s);
    op(s);
    op(s);
}

void call_addr(state* s)
{
    op_fn addr = (op_fn)0xaabbccdd;
    addr(s);
}

op_fn get_addr()
{
    return add;
}

typedef void(*dispatch_fn)(state *s);

void make_dispatch_code(void* mem)
{
    uint8_t *it = (uint8_t *)mem;

    size_t addr_full = (size_t)add;
    assert(addr_full < UINT32_MAX);
    uint32_t addr = (uint32_t)addr_full;

    *it++ = '\x53';  // push %rbx

    *it++ = '\x48';  // mov %rdi (first arg) -> %rbx
    *it++ = '\x89';
    *it++ = '\xfb';

    for (int i = 0; i < 19; ++i)
    {
        *it++ = '\x48'; // mov %rbx -> %rdi
        *it++ = '\x89';
        *it++ = '\xdf';

        *it++ = '\xb8'; // mov addr -> %eax
        memcpy(it, &addr, sizeof(addr));
        it += sizeof(addr);

        *it++ = '\xff'; // callq  *%rax
        *it++ = '\xd0';
    }

    *it++ = '\x5b'; // pop %rbx

    *it++ = '\xc3'; // ret

    *it++ = 0;
}

int main()
{
    const size_t mem_size = 4096;
    void *exec_mem = mmap(NULL, mem_size, PROT_EXEC | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    // memcpy(exec_mem, noop_code, strlen(noop_code));
    printf("executable memory address: %p\n", exec_mem);
    printf("&add(): %p\n", add);

    make_dispatch_code(exec_mem);
    print_hex((char*)exec_mem);

    state s;
    for (int b = 0; b < 1000000; ++b)
    {
        s.stack_size = 0;
        for (int i = 0; i < 20; ++i)
        {
            s.stack[i] = i + 1;
            s.stack_size++;
        }

        dispatch_fn disp = (dispatch_fn)exec_mem;
        disp(&s);
    }

    return s.stack[0];
}
