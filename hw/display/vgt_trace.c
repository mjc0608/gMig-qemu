#include "trace.h"
#include "vgt_logd.h"
#include "qemu/bitmap.h"
#include "qemu/bitops.h"
#include "vgt_trace.h"
#include "qemu/rcu_queue.h"

static unsigned long *vgt_dirty_bitmap;
static unsigned long *vgt_vgpu_bitmap;
static unsigned long *vgt_vcpu_bitmap;
static unsigned long ram_npages;
static unsigned long ngpunew;
bool vgpu_dirty_tracing;

static void init_vgpu_tracing(void) {
    ram_npages = last_ram_offset() >> TARGET_PAGE_BITS;
    ngpunew = 0;
    vgt_dirty_bitmap = bitmap_new(ram_npages);
    vgt_vgpu_bitmap = bitmap_new(ram_npages);
    vgt_vcpu_bitmap = bitmap_new(ram_npages);
    bitmap_clear(vgt_dirty_bitmap, 0, ram_npages);
    bitmap_clear(vgt_vgpu_bitmap, 0, ram_npages);
    bitmap_clear(vgt_vcpu_bitmap, 0, ram_npages);
}

static unsigned long get_vcpu_dirtied_count(void) {
    unsigned long i, ndirty = 0, bitmap_longs = ram_npages/64;

    for (i=0; i<bitmap_longs; i++) {
        ndirty += ctpopl(vgt_vcpu_bitmap[i]);
    }
    for (i=i*64; i<ram_npages; i++) {
        ndirty += test_bit(i, vgt_vcpu_bitmap);
    }

    return ndirty;
}

static unsigned long get_vgpu_dirtied_count(void) {
    unsigned long i, ndirty = 0, bitmap_longs = ram_npages/64;

    for (i=0; i<bitmap_longs; i++) {
        ndirty += ctpopl(vgt_dirty_bitmap[i]);
    }
    for (i=i*64; i<ram_npages; i++) {
        ndirty += test_bit(i, vgt_dirty_bitmap);
    }

    return ndirty;
}

static unsigned long get_vgpu_related_count(void) {
    unsigned long i, ndirty = 0, bitmap_longs = ram_npages/64;

    for (i=0; i<bitmap_longs; i++) {
        ndirty += ctpopl(vgt_vgpu_bitmap[i]);
    }
    for (i=i*64; i<ram_npages; i++) {
        ndirty += test_bit(i, vgt_vgpu_bitmap);
    }

    return ndirty;
}

static unsigned long get_both_dirtied_count(void) {
    unsigned long i, ndirty = 0, bitmap_longs = ram_npages/64;

    for (i=0; i<bitmap_longs; i++) {
        ndirty += ctpopl(vgt_dirty_bitmap[i] & vgt_vcpu_bitmap[i]);
    }
    for (i=i*64; i<ram_npages; i++) {
        ndirty += (test_bit(i, vgt_dirty_bitmap) && test_bit(i, vgt_vcpu_bitmap));
    }

    return ndirty;
}

static inline void vgpu_bitmap_set_dirty(ram_addr_t addr)
{
    int nr = addr >> TARGET_PAGE_BITS;
    set_bit(nr, vgt_vgpu_bitmap);
}

static inline void vcpu_bitmap_set_dirty(ram_addr_t addr)
{
    int nr = addr >> TARGET_PAGE_BITS;
    set_bit(nr, vgt_vcpu_bitmap);
}

static inline void vcpu_bitmap_clear_dirty(ram_addr_t addr)
{
    int nr = addr >> TARGET_PAGE_BITS;
    clear_bit(nr, vgt_vcpu_bitmap);
}

static void vcpu_bitmap_sync_range(ram_addr_t start, ram_addr_t length)
{
    ram_addr_t addr;
    unsigned long page = BIT_WORD(start >> TARGET_PAGE_BITS);

    /* start address is aligned at the start of a word? */
    if (((page * BITS_PER_LONG) << TARGET_PAGE_BITS) == start) {
        int k;
        int nr = BITS_TO_LONGS(length >> TARGET_PAGE_BITS);
        unsigned long *src = ram_list.dirty_memory[DIRTY_MEMORY_MIGRATION];

        for (k = page; k < page + nr; k++) {
            if (src[k]) {
                vgt_vcpu_bitmap[k] |= src[k];
                src[k] = 0;
            }
        }
    } else {
        for (addr = 0; addr < length; addr += TARGET_PAGE_SIZE) {
            if (cpu_physical_memory_get_dirty(start + addr,
                                              TARGET_PAGE_SIZE,
                                              DIRTY_MEMORY_MIGRATION)) {
                cpu_physical_memory_reset_dirty(start + addr,
                                                TARGET_PAGE_SIZE,
                                                DIRTY_MEMORY_MIGRATION);
                vcpu_bitmap_set_dirty(start + addr);
            }
        }
    }
}

#if 1
static void vcpu_bitmap_clear_range(ram_addr_t start, ram_addr_t length)
{
    ram_addr_t addr;
    unsigned long page = BIT_WORD(start >> TARGET_PAGE_BITS);

    /* start address is aligned at the start of a word? */
    if (((page * BITS_PER_LONG) << TARGET_PAGE_BITS) == start) {
        int k;
        int nr = BITS_TO_LONGS(length >> TARGET_PAGE_BITS);
        unsigned long *src = ram_list.dirty_memory[DIRTY_MEMORY_MIGRATION];

        for (k = page; k < page + nr; k++) {
            vgt_vcpu_bitmap[k] = 0;
            src[k] = 0;
        }
    } else {
        for (addr = 0; addr < length; addr += TARGET_PAGE_SIZE) {
            if (cpu_physical_memory_get_dirty(start + addr,
                                              TARGET_PAGE_SIZE,
                                              DIRTY_MEMORY_MIGRATION)) {
                cpu_physical_memory_reset_dirty(start + addr,
                                                TARGET_PAGE_SIZE,
                                                DIRTY_MEMORY_MIGRATION);
                vcpu_bitmap_clear_dirty(start + addr);
            }
        }
    }
}
#endif

static void vgpu_bitmap_sync_range(ram_addr_t start, ram_addr_t length)
{
    ram_addr_t addr;
    unsigned long page = BIT_WORD(start >> TARGET_PAGE_BITS);

    /* start address is aligned at the start of a word? */
    if (((page * BITS_PER_LONG) << TARGET_PAGE_BITS) == start) {
        int k;
        int nr = BITS_TO_LONGS(length >> TARGET_PAGE_BITS);
        unsigned long *src = ram_list.dirty_memory[DIRTY_MEMORY_VGPU];

        for (k = page; k < page + nr; k++) {
            if (src[k]) {
                vgt_vgpu_bitmap[k] |= src[k];
            }
        }
    } else {
        for (addr = 0; addr < length; addr += TARGET_PAGE_SIZE) {
            if (cpu_physical_memory_get_dirty(start + addr,
                                              TARGET_PAGE_SIZE,
                                              DIRTY_MEMORY_VGPU)) {
                vgpu_bitmap_set_dirty(start + addr);
            }
        }
    }
}

static inline
ram_addr_t vgpu_bitmap_find_and_reset_dirty(MemoryRegion *mr,
                                                 ram_addr_t start)
{
    unsigned long base = mr->ram_addr >> TARGET_PAGE_BITS;
    unsigned long nr = base + (start >> TARGET_PAGE_BITS);
    uint64_t mr_size = TARGET_PAGE_ALIGN(memory_region_size(mr));
    unsigned long size = base + (mr_size >> TARGET_PAGE_BITS);

    unsigned long next;

    next = find_next_bit(vgt_vgpu_bitmap, size, nr);

    if (next < size) {
        clear_bit(next, vgt_vgpu_bitmap);
    }
    return (next - base) << TARGET_PAGE_BITS;
}

static void vgpu_bitmap_sync(void) {
    RAMBlock *block;
    address_space_sync_dirty_bitmap(&address_space_memory);
    QLIST_FOREACH_RCU(block, &ram_list.blocks, next) {
        vgpu_bitmap_sync_range(block->mr->ram_addr, block->used_length);
        vcpu_bitmap_sync_range(block->mr->ram_addr, block->used_length);
    }
}

static uint8_t pp[TARGET_PAGE_SIZE];
static void gm_compare_page(RAMBlock *block, ram_addr_t offset, bool first_stage) {
    ram_addr_t current_addr;
    MemoryRegion *mr = block->mr;
    uint8_t *p;
    uint64_t gfn;

    assert(mr);

    p = memory_region_get_ram_ptr(mr) + offset;
    current_addr = block->offset + offset;
    gfn = current_addr >> TARGET_PAGE_BITS;

    memcpy(pp, p, TARGET_PAGE_SIZE);
    p = pp;

    if (first_stage) {
        vgt_hash_a_page(p, gfn);
    }
    else {
        if (!vgt_gpu_releated(gfn)) {
            ngpunew++;
            vgt_hash_a_page(p, gfn);
        }
        else if (vgt_page_is_modified(p, gfn)) {
            set_bit(gfn, vgt_dirty_bitmap);
        }
    }
}

static void gm_compare_iterate(bool first_stage) {
    RAMBlock *block;

    QLIST_FOREACH_RCU(block, &ram_list.blocks, next) {
        ram_addr_t offset = 0;
        MemoryRegion *mr = block->mr;

        while (1) {
            offset = vgpu_bitmap_find_and_reset_dirty(mr, offset);
            if (offset >= block->used_length) break;
            gm_compare_page(block, offset, first_stage);
        }
    }
}

static uint64_t tracing_time_base_ms;
static inline void init_tracing_time(void) {
    tracing_time_base_ms = qemu_clock_get_ms(QEMU_CLOCK_HOST);
}

static inline uint64_t get_tracing_time(void) {
    return (qemu_clock_get_ms(QEMU_CLOCK_HOST) - tracing_time_base_ms);
}

static void* vgt_tracing_thread(void * opaque) {
    uint64_t t1, t2, ngpudirty, ncpudirty, nbothdirty, nrelated;
    RAMBlock *block;

    init_vgpu_tracing();
    memory_global_dirty_log_start();

    vgpu_bitmap_sync();
    QLIST_FOREACH_RCU(block, &ram_list.blocks, next) {
        vcpu_bitmap_clear_range(block->mr->ram_addr, block->used_length);
    }


    init_tracing_time();
    vgpu_dirty_tracing = true;

    vgpu_bitmap_sync();

    gm_compare_iterate(true);

    while (1) {
//        g_usleep(50000);

        bitmap_clear(vgt_dirty_bitmap, 0, ram_npages);
        bitmap_clear(vgt_vcpu_bitmap, 0, ram_npages);

        vgpu_bitmap_sync();

        t1 = get_tracing_time();
        gm_compare_iterate(false);
        t2 = get_tracing_time();

        ngpudirty = get_vgpu_dirtied_count();
        ncpudirty = get_vcpu_dirtied_count();
        nbothdirty = get_both_dirtied_count();

        trace_gpu_dirty_speed(t1, ngpudirty/(t2-t1), ncpudirty/(t2-t1));
    }

    return NULL;
}

static QemuThread tracing_thread;
void vgt_start_tracing(void) {
    qemu_thread_create(&tracing_thread, "gdirty", vgt_tracing_thread,
            NULL, QEMU_THREAD_JOINABLE);
}

