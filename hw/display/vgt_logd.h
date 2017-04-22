/*
 * Some IO devices like GPU will modify RAM, however these devices do not
 * has dirty bit support in their page table. While migrating these devices,
 * we have to use method like hashing to find out if a page accessed by
 * them is modified.
 */
#ifndef RAM_VGT_H
#define RAM_VGT_H

#include "hw/hw.h"
#include "ui/console.h"
#include "hw/i386/pc.h"
#include "hw/pci/pci.h"
#include "hw/pci/pci_host.h"
#include "hw/pci/pci_bridge.h"
#include "hw/pci/pci_bus.h"
#include "vga_int.h"
#include "ui/pixel_ops.h"
#include "qemu/timer.h"
#include "hw/loader.h"
#include "qemu/log.h"
#include "sysemu/arch_init.h"
#include "hw/xen/xen.h"
#include "exec/ram_addr.h"

/* each logd_slot_t cover 4M guest memory range */
#define LOGD_SLOT_SIZE 1024
#define LOGD_HASH_SIZE 32
#define VGT_PAGE_SHIFT 12

/* 256bit hash value */
typedef struct logd_tag_t {
    uint8_t data[LOGD_HASH_SIZE];
} logd_tag_t;

typedef struct logd_tag_block_t {
    logd_tag_t block[LOGD_SLOT_SIZE];
} logd_tag_block_t;

typedef struct logd_slot_t {
    logd_tag_block_t *logd_tag_block;
    unsigned long *logd_dirty_bitmap;
} logd_slot_t;

/* simple array instead of list for quick slot search */
typedef struct vgt_logd_t {
    logd_slot_t *slot_head;
    unsigned long max_gpfn;
    unsigned long max_slot;
} vgt_logd_t;

bool vgt_page_is_modified(void *va, unsigned long gfn);
void vgt_hash_a_page(void *va, unsigned long gfn);
bool vgt_gpu_releated(unsigned long gfn);

#endif
