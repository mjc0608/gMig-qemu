#include "vgt_logd.h"
#include "qemu/bitmap.h"
#include "qemu/bitops.h"
#include "xxhash.h"

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

#if 0
static inline
vgt_logd_t* vgt_logd_init(void) {
    vgt_logd_t *logd = g_malloc0(sizeof(vgt_logd_t));
    logd->slot_head = NULL;
    logd->max_gpfn = 0;
    logd->max_slot = 0;

    return logd;
}
#endif

static inline
void vgt_logd_finit(vgt_logd_t *logd) {
    unsigned long i;

    for (i=0; i<logd->max_slot; i++) {
        logd_tag_block_t *tag_block = logd->slot_head[i].logd_tag_block;
        unsigned long *slot_dirty_bitmap = logd->slot_head[i].logd_dirty_bitmap;

        if (tag_block != NULL) g_free(tag_block);
        if (slot_dirty_bitmap != NULL) g_free(slot_dirty_bitmap);
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
void logd_hash_a_page(vgt_logd_t *logd, void *va, unsigned long gfn) {
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

    if (slot->logd_dirty_bitmap == NULL) {
        slot->logd_dirty_bitmap = logd_alloc_dirty_bitmap();
        if (slot->logd_tag_block == NULL) {
            DPRINTF("Failed to increase bitmap\n");
        }
        bitmap_clear(slot->logd_dirty_bitmap, 0, LOGD_SLOT_SIZE);
    }

    set_bit(TAG_OFFSET(gfn), slot->logd_dirty_bitmap);


    logd_tag_t *tag = slot->logd_tag_block->block + TAG_OFFSET(gfn);
    hash_of_page_256bit(va, tag);
}

static inline
bool logd_page_rehash_and_test(vgt_logd_t *logd, void *va, unsigned long gfn) {
    assert(logd!=NULL);
    assert(va!=NULL);

    if (SLOT_OFFSET(gfn) > logd->max_slot) return true;

    logd_slot_t *slot = GET_SLOT(logd, gfn);
    assert(slot);

    if (slot->logd_tag_block == NULL) return true;
    if (slot->logd_dirty_bitmap == NULL) return true;

    if (test_bit(TAG_OFFSET(gfn), slot->logd_dirty_bitmap)==0) return true;

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
    if (slot->logd_dirty_bitmap == NULL) return false;

    if (test_bit(TAG_OFFSET(gfn), slot->logd_dirty_bitmap)==0) return false;

    return true;
}

