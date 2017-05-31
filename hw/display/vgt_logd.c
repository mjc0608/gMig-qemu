#include "vgt_logd.h"
#include "qemu/bitmap.h"
#include "qemu/bitops.h"
#include "xxhash.h"
#include "trace.h"
#include "vgt_logd.h"
#include "qemu/rcu_queue.h"

#define DEBUG_MIG_VGT
#ifdef DEBUG_MIG_VGT
#define DPRINTF(fmt, ...) \
    do { fprintf(stderr, "RAM_VGT: " fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif


#define SLOT_OFFSET(gfn) \
    ((gfn) / LOGD_SLOT_SIZE)

#define TAG_OFFSET(gfn) \
    ((gfn) % LOGD_SLOT_SIZE)

#define GET_SLOT(logd, gfn) \
    ((logd)->slot_head + SLOT_OFFSET(gfn))

static vgt_logd_t vgt_logd = {
    .slot_head = NULL,
    .max_gpfn = 0,
    .max_slot = 0
};

static unsigned long *logd_dirty_bitmap;
static unsigned long max_sent_gpfn = 0;
static QemuThread vgt_prehashing_thread;
static unsigned long *logd_pre_dirty_bitmap;
static unsigned long ram_npages;

/* when the slot array is not large enough, we have to increase it */
static inline
bool logd_increase_slot_count(vgt_logd_t *logd, unsigned long gfn) {
    unsigned long new_slot_offset = SLOT_OFFSET(gfn);
    unsigned long old_slot_offset = logd->max_slot;


    if (new_slot_offset <= old_slot_offset && logd->slot_head)
        return true;

    unsigned long new_max_gpfn = gfn;
    int new_slot_count = (new_slot_offset + 1)*2;
    int old_slot_count = old_slot_offset + 1;
    logd_slot_t *new_slot_head;
    logd_slot_t *old_slot_head = logd->slot_head;
    new_slot_offset = new_slot_count - 1;

    new_slot_head = g_malloc0(new_slot_count * sizeof(logd_slot_t));
    if (new_slot_head==NULL) {
        DPRINTF("Failed to increase slot count, size=0x%lx\n",
                    new_slot_count * sizeof(logd_slot_t));
        return false;
    }

    if (logd->slot_head) {
        memcpy(new_slot_head, old_slot_head, old_slot_count * sizeof(logd_slot_t));
        g_free(logd->slot_head);
    }
    logd->slot_head = new_slot_head;
    logd->max_gpfn = new_max_gpfn;
    logd->max_slot = new_slot_offset;

    return true;
}

void vgt_logd_init(void) {
    ram_npages = last_ram_offset() >> TARGET_PAGE_BITS;
    logd_pre_dirty_bitmap = bitmap_new(ram_npages);
    logd_dirty_bitmap = bitmap_new(ram_npages);
    bitmap_clear(logd_pre_dirty_bitmap, 0, ram_npages);
    bitmap_clear(logd_dirty_bitmap, 0, ram_npages);

    vgt_start_prehashing();
}

static inline
void vgt_logd_finit(vgt_logd_t *logd) {
    unsigned long i;

    for (i=0; i<logd->max_slot; i++) {
        logd_tag_block_t *tag_block = logd->slot_head[i].logd_tag_block;

        if (tag_block != NULL) g_free(tag_block);
    }

    g_free(logd->slot_head);
    logd->slot_head = NULL;
    logd->max_gpfn = 0;
    logd->max_slot = 0;
}

static inline
logd_tag_block_t* logd_alloc_tag_block(void) {
    logd_tag_block_t *tag_block = g_malloc0(sizeof(*tag_block));
    return tag_block;
}

static inline
unsigned long* logd_alloc_dirty_bitmap(void) {
    unsigned long *bitmap = bitmap_new(LOGD_SLOT_SIZE);
    return bitmap;
}

static bool hash_of_page_256bit(void* va, void* target) {
    return XXH256(va, 4096, 0, target);
}

static inline
bool logd_hash_a_page(vgt_logd_t *logd, void *va, unsigned long gfn) {
    assert(logd!=NULL);
    assert(va!=NULL);

    logd_increase_slot_count(logd, gfn);

    logd_slot_t *slot = GET_SLOT(logd, gfn);
    assert(slot);
    if (slot->logd_tag_block == NULL) {
        slot->logd_tag_block = logd_alloc_tag_block();
        if (slot->logd_tag_block == NULL) {
            DPRINTF("Failed to increase slot count, size=0x%lx\n",
                        sizeof(logd_tag_block_t));
        }
    }


    if (gfn > max_sent_gpfn) max_sent_gpfn = gfn;

    logd_tag_t *tag = slot->logd_tag_block->block + TAG_OFFSET(gfn);
    bool is_modified = hash_of_page_256bit(va, tag);
    set_bit(gfn, logd_dirty_bitmap);
    return is_modified;
}

static inline
bool logd_page_rehash_and_test(vgt_logd_t *logd, void *va, unsigned long gfn) {
    assert(logd!=NULL);
    assert(va!=NULL);

    if (SLOT_OFFSET(gfn) > logd->max_slot) return true;

    logd_slot_t *slot = GET_SLOT(logd, gfn);
    assert(slot);

    if (slot->logd_tag_block == NULL) return true;

    if (test_bit(gfn, logd_dirty_bitmap)==0) return true;

    logd_tag_t *tag = slot->logd_tag_block->block + TAG_OFFSET(gfn);

    bool is_modified = hash_of_page_256bit(va, tag);

    return is_modified;
}


/* test if a page is modified by comparing it's hash value */
bool vgt_page_is_modified(void *va, unsigned long gfn) {
    bool ret = logd_page_rehash_and_test(&vgt_logd, va, gfn);
    return ret;
}

void vgt_hash_a_page(void *va, unsigned long gfn) {
    logd_hash_a_page(&vgt_logd, va, gfn);
}

bool vgt_gpu_releated(unsigned long gfn) {
    vgt_logd_t *logd = &vgt_logd;
    if (SLOT_OFFSET(gfn) > logd->max_slot) return false;

    logd_slot_t *slot = GET_SLOT(logd, gfn);
    if (slot == NULL) return false;

    if (slot->logd_tag_block == NULL) return false;

    if (test_bit(gfn, logd_dirty_bitmap)==0) return false;

    return true;
}


/*******************************************************************************/
/* vgt_prehashing */


bool vgt_page_is_predirtied(unsigned long gfn) {
    return test_bit(gfn, logd_pre_dirty_bitmap);
}

void* vgt_get_prehashing_dirty_bitmap(void) {
    return logd_pre_dirty_bitmap;
}

static inline
void prehashing_exit(void)
{
//    printf("spin on complete stage...\n");
    while (1)
        g_usleep(100000000);
}

static inline
ram_addr_t vgpu_bitmap_find_dirty(MemoryRegion *mr,
                                                 ram_addr_t start)
{
    unsigned long base = mr->ram_addr >> TARGET_PAGE_BITS;
    unsigned long nr = base + (start >> TARGET_PAGE_BITS);
    uint64_t mr_size = TARGET_PAGE_ALIGN(memory_region_size(mr));
    unsigned long size = base + (mr_size >> TARGET_PAGE_BITS);

    unsigned long next;

    next = find_next_bit(logd_dirty_bitmap, size, nr);

    return (next - base) << TARGET_PAGE_BITS;
}

extern bool is_complete_stage;
static void
vgt_prehashing_iterate(void) {
    RAMBlock *block;

    QLIST_FOREACH_RCU(block, &ram_list.blocks, next) {
        ram_addr_t offset = 0;
        ram_addr_t curr_addr;
        MemoryRegion *mr = block->mr;
        bool is_modified;
        uint8_t *p;
        uint64_t gfn;

        while (1) {
            offset = vgpu_bitmap_find_dirty(mr, offset);
            if (offset >= block->used_length) break;
            curr_addr = block->offset + offset;
            gfn = curr_addr >> VGT_PAGE_SHIFT;
            int wait_cnt = 0;

            while (gfn >= max_sent_gpfn) {
                wait_cnt++;
                if (wait_cnt>1) return;
                g_usleep(50000);
            }
            if (is_complete_stage) prehashing_exit();

            p = memory_region_get_ram_ptr(mr) + offset;

            is_modified = logd_hash_a_page(&vgt_logd, p, gfn);

            if (is_modified) {
                set_bit(gfn, logd_pre_dirty_bitmap);
            }
            offset+=4096;
        }
    }
}

static void*
do_vgt_prehashing_thread(void *opaque) {
    while (1) {
        g_usleep(50000);
        vgt_prehashing_iterate();
    }
    return NULL;
}

void vgt_start_prehashing(void) {
    qemu_thread_create(&vgt_prehashing_thread, "prehashing",
            do_vgt_prehashing_thread, NULL, QEMU_THREAD_JOINABLE);
}
