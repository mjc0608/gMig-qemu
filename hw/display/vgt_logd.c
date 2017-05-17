#include "vgt_logd.h"
#include "qemu/bitmap.h"
#include "qemu/bitops.h"
#include <inttypes.h>

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

static bool sha_for_page(char* pp, char* target);

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

extern bool hash_of_page_256bit(void* va, void* target);

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
    sha_for_page(va, (char*)tag);
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

    bool is_modified = sha_for_page(va, (char*)tag);

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

static bool sha_for_page(char* pp, char* target) {
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xEFCDAB89;
    uint32_t h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476;
    uint32_t h4 = 0xC3D2E1F0;
    int i, j, temp;
    uint32_t a, b, c, d, e, f, k;

    for (i=0; i<4096; i+=64) {
        uint32_t *chunk = (uint32_t*)(pp+i);
        uint32_t w[80];
        for (j=0; j<16; j++) {
            w[j] = chunk[j];
        }
        
        for (j=16; j<=79; j++) {
            temp = (w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16]);
            w[j] = ((temp<<1) | (temp>>31));
        }

        a = h0;
        b = h1;
        c = h2;
        d = h3;
        e = h4;

        for (j=0; j<=79; j++) {
            if (0<=j && j<=19) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            }
            else if (20<=j && j<=39) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            }
            else if (40<=j && j<=59) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            }
            else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }

            temp = ((a<<5) | (a>>27)) + f + e + k + w[j];
            e = d;
            d = c;
            c = (b<<30) | (b>>2);
            b = a;
            a = temp;
        }
        h0 = h0 + a;
        h1 = h1 + b;
        h2 = h2 + c;
        h3 = h3 + d;
        h4 = h4 + e;
    }

    bool ret = false;

    if (*((uint32_t*)(target)) != h0) ret = true;
    if (*((uint32_t*)(target+4)) != h1) ret = true;
    if (*((uint32_t*)(target+8)) != h2) ret = true;
    if (*((uint32_t*)(target+12)) != h3) ret = true;
    if (*((uint32_t*)(target+16)) != h4) ret = true;

    if (ret) return true;

    *((uint32_t*)(target)) = h0;
    *((uint32_t*)(target+4)) = h1;
    *((uint32_t*)(target+8)) = h2;
    *((uint32_t*)(target+12)) = h3;
    *((uint32_t*)(target+16)) = h4;

    return false;
}
