/*
 * QEMU vGT/XenGT Legacy VGA support
 *
 * Copyright (c) 2003 Fabrice Bellard
 * Copyright (c) Citrix Systems, Inc
 * Copyright (c) Intel Corporation.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
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

//#define DEBUG_VGT

#ifdef DEBUG_VGT
#define DPRINTF(fmt, ...) \
    do { fprintf(stderr, "vgt: " fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

typedef struct VGTHostDevice {
    PCIHostDeviceAddress addr;
    int config_fd;
    uint16_t vendor_id;
    uint16_t device_id;
    uint8_t revision_id;
    uint16_t class_dev;
} VGTHostDevice;

typedef struct VGTVGAState {
    PCIDevice dev;
    struct VGACommonState state;
    int num_displays;
    VGTHostDevice host_dev;
    bool instance_created;
} VGTVGAState;

#define EDID_SIZE 128
#define MAX_INPUT_NUM 3
#define MAX_PORT_TYPE 4
#define MAX_FILE_NAME_LENGTH 128

typedef struct VGTMonitorInfo {
    unsigned char port_type;
    unsigned char port_override;
    unsigned char edid[EDID_SIZE];
}VGTMonitorInfo;

/* These are the default values */
int vgt_low_gm_sz = 64; /* in MB */
int vgt_high_gm_sz = 448; /* in MB */
int vgt_fence_sz = 4;
int vgt_primary = 1; /* -1 means "not specified */
const char *vgt_monitor_config_file = NULL;

static int vgt_host_device_get(VGTHostDevice *dev);
static void vgt_host_device_put(VGTHostDevice *dev);

static bool validate_monitor_configs(VGTMonitorInfo *config)
{
    if (config->port_type > MAX_PORT_TYPE) {
        qemu_log("vGT: %s failed because the invalid port_type input: %d!\n",
            __func__, config->port_type);
        return false;
    }
    if (config->port_override > MAX_PORT_TYPE) {
        qemu_log("vGT: %s failed due to the invalid port_override input: %d!\n",
            __func__, config->port_override);
        return false;
    }
    if (config->edid[126] != 0) {
        qemu_log("vGT: %s failed because there is extended block in EDID! "
            "(EDID[126] is not zero)\n", __func__);
        return false;
    }

    return true;
}

static void config_hvm_monitors(VGTMonitorInfo *config)
{
    const char *path_prefix = "/sys/kernel/vgt/vm";
    FILE *fp;
    char file_name[MAX_FILE_NAME_LENGTH];
    int ret;

    // override
    snprintf(file_name, MAX_FILE_NAME_LENGTH, "%s%d/PORT_%c/port_override",
        path_prefix, xen_domid, 'A' + config->port_type);
    if ((fp = fopen(file_name, "w")) == NULL) {
        qemu_log("vGT: %s failed to open file %s! errno = %d\n",
            __func__, file_name, errno);
        return;
    }
    fprintf(fp, "PORT_%c", 'A' + config->port_override);
    if (fclose(fp) != 0) {
        qemu_log("vGT: %s failed to close file: errno = %d\n", __func__, errno);
    }

    // edid
    snprintf(file_name, MAX_FILE_NAME_LENGTH, "%s%d/PORT_%c/edid",
        path_prefix, xen_domid, 'A' + config->port_type);
    if ((fp = fopen(file_name, "w")) == NULL) {
        qemu_log("vGT: %s failed to open file %s! errno = %d\n",
            __func__, file_name, errno);
        return;
    }
    ret = fwrite(config->edid, 1, EDID_SIZE, fp);
    if (ret != EDID_SIZE) {
        qemu_log("vGT: %s failed to write EDID with returned size %d: "
            "errno = %d\n", __func__, ret, errno);
    }
    if (fclose(fp) != 0) {
        qemu_log("vGT: %s failed to close file: errno = %d\n", __func__, errno);
    }

    // flush result to port structure
    snprintf(file_name, MAX_FILE_NAME_LENGTH, "%s%d/PORT_%c/connection",
        path_prefix, xen_domid, 'A' + config->port_type);
    if ((fp = fopen(file_name, "w")) == NULL) {
        qemu_log("vGT: %s failed to open file %s! errno = %d\n",
            __func__, file_name, errno);
        return;
    }
    fprintf(fp, "flush");
    if (fclose(fp) != 0) {
        qemu_log("vGT: %s failed to close file: errno = %d\n", __func__, errno);
    }
}

#define CTOI(chr) \
    (chr >= '0' && chr <= '9' ? chr - '0' : \
    (chr >= 'a' && chr <= 'f' ? chr - 'a' + 10 :\
    (chr >= 'A' && chr <= 'F' ? chr - 'A' + 10 : -1)))

static int get_byte_from_txt_file(FILE *file, const char *file_name)
{
    int i;
    int val[2];

    for (i = 0; i < 2; ++ i) {
        do {
            unsigned char buf;
            if (fread(&buf, 1, 1, file) != 1) {
                qemu_log("vGT: %s failed to get byte from text file %s with errno: %d!\n",
                    __func__, file_name, errno);
                return -1;
            }

            if (buf == '#') {
                // ignore comments
                int ret;
                while (((ret = fread(&buf, 1, 1, file)) == 1) && (buf != '\n')) ;
                if (ret != 1) {
                    qemu_log("vGT: %s failed to proceed after comment string "
                            "from text file %s with errno: %d!\n",
                            __func__, file_name, errno);
                    return -1;
                }
            }

            val[i] = CTOI(buf);
        } while (val[i] == -1);
    }

    return ((val[0] << 4) | val[1]);
}

static int get_config_header(unsigned char *buf, FILE *file, const char *file_name)
{
    int ret;
    unsigned char chr;

    if (fread(&chr, 1, 1, file) != 1) {
        qemu_log("vGT: %s failed to get byte from text file %s with errno: %d!\n",
            __func__, file_name, errno);
        return -1;
    }

    if (chr == '#') {
        // it is text format input.
        while (((ret = fread(&chr, 1, 1, file)) == 1) && (chr != '\n')) ;
        if (ret != 1) {
            qemu_log("vGT: %s failed to proceed after comment string "
                "from file %s with errno: %d!\n",
                __func__, file_name, errno);
            return -1;
        }
        ret = get_byte_from_txt_file(file, file_name);
        buf[0] = 1;
        buf[1] = (ret & 0xf);
    } else {
        if ((ret = fread(&buf[0], 1, 2, file)) != 2) {
            qemu_log("vGT: %s failed to read file %s! "
                "Expect to read %d bytes but only got %d bytes! errno: %d\n",
                __func__, file_name, 2, ret, errno);
            return -1;
        }

        if (buf[0] != 0) {
            // it is text format input.
            buf[1] -= '0';
        }
    }

    return 0;
}

static void config_vgt_guest_monitors(void)
{
    FILE *monitor_config_f;
    unsigned char buf[4];
    VGTMonitorInfo monitor_configs[MAX_INPUT_NUM];
    bool text_mode;
    int input_items;
    int ret, i;

    if (!vgt_monitor_config_file) {
        return;
    }

    if ((monitor_config_f = fopen(vgt_monitor_config_file, "r")) == NULL) {
        qemu_log("vGT: %s failed to open file %s! errno = %d\n",
            __func__, vgt_monitor_config_file, errno);
        return;
    }

    if (get_config_header(buf, monitor_config_f, vgt_monitor_config_file) != 0) {
        goto finish_config;
    }

    text_mode = !!buf[0];
    input_items = buf[1];

    if (input_items <= 0 || input_items > MAX_INPUT_NUM) {
        qemu_log("vGT: %s, Out of range input of the number of items! "
            "Should be [1 - 3] but input is %d\n", __func__, input_items);
        goto finish_config;
    }

    if (text_mode) {
        unsigned int total = sizeof(VGTMonitorInfo) * input_items;
        unsigned char *p = (unsigned char *)monitor_configs;
        for (i = 0; i < total; ++i, ++p) {
            unsigned int val = get_byte_from_txt_file(monitor_config_f,
                vgt_monitor_config_file);
            if (val == -1) {
                break;
            } else {
                *p = val;
            }
        }
        if (i < total) {
            goto finish_config;
        }
    } else {
        unsigned int total = sizeof(VGTMonitorInfo) * input_items;
        ret = fread(monitor_configs, sizeof(VGTMonitorInfo), input_items,
                    monitor_config_f);
        if (ret != total) {
            qemu_log("vGT: %s failed to read file %s! "
                "Expect to read %d bytes but only got %d bytes! errno: %d\n",
                 __func__, vgt_monitor_config_file, total, ret, errno);
            goto finish_config;
        }
    }

    for (i = 0; i < input_items; ++ i) {
        if (validate_monitor_configs(&monitor_configs[i]) == false) {
            qemu_log("vGT: %s the monitor config[%d] input from %s is not valid!\n",
                __func__, i, vgt_monitor_config_file);
            goto finish_config;
        }
    }
    for (i = 0; i < input_items; ++ i) {
        config_hvm_monitors(&monitor_configs[i]);
    }

finish_config:
    if (fclose(monitor_config_f) != 0) {
        qemu_log("vGT: %s failed to close file %s: errno = %d\n", __func__,
            vgt_monitor_config_file, errno);
    }
    return;
}

void vgt_bridge_pci_write(PCIDevice *dev,
                          uint32_t address, uint32_t val, int len)
{
#if 0
    VGTVGAState *o = DO_UPCAST(VGTVGAState, dev, dev);
#endif

    assert(dev->devfn == 0x00);

//  fprintf("vGT Config Write: addr=%x len=%x val=%x\n", addr, len, val);

    switch (address) {
#if 0
        case 0x58:        // PAVPC Offset
            xen_host_pci_set_block(o->host_dev, addr, val, len);
            break;
#endif
    }

    i440fx_write_config(dev, address, val, len);
}

/*
 *  Inform vGT driver to create a vGT instance
 */
static void create_vgt_instance(void)
{
    /* FIXME: this should be substituded as a environment variable */
    const char *path = "/sys/kernel/vgt/control/create_vgt_instance";
    FILE *vgt_file;
    int err = 0;

    qemu_log("vGT: %s: domid=%d, low_gm_sz=%dMB, high_gm_sz=%dMB, "
        "fence_sz=%d, vgt_primary=%d\n", __func__, xen_domid,
        vgt_low_gm_sz, vgt_high_gm_sz, vgt_fence_sz, vgt_primary);
    if (vgt_low_gm_sz <= 0 || vgt_high_gm_sz <=0 ||
		vgt_primary < -1 || vgt_primary > 1 ||
        vgt_fence_sz <=0) {
        qemu_log("vGT: %s failed: invalid parameters!\n", __func__);
        abort();
    }

    if ((vgt_file = fopen(path, "w")) == NULL) {
        err = errno;
        qemu_log("vGT: open %s failed\n", path);
    }
    /* The format of the string is:
     * domid,aperture_size,gm_size,fence_size. This means we want the vgt
     * driver to create a vgt instanc for Domain domid with the required
     * parameters. NOTE: aperture_size and gm_size are in MB.
     */
    if (!err && fprintf(vgt_file, "%d,%u,%u,%u,%d\n", xen_domid,
        vgt_low_gm_sz, vgt_high_gm_sz, vgt_fence_sz, vgt_primary) < 0) {
        err = errno;
    }

    if (!err && fclose(vgt_file) != 0) {
        err = errno;
    }

    if (err) {
        qemu_log("vGT: %s failed: errno=%d\n", __func__, err);
        exit(-1);
    }

    config_vgt_guest_monitors();
}

/*
 *  Inform vGT driver to close a vGT instance
 */
static void destroy_vgt_instance(void)
{
    const char *path = "/sys/kernel/vgt/control/create_vgt_instance";
    FILE *vgt_file;
    int err = 0;

    if ((vgt_file = fopen(path, "w")) == NULL) {
        error_report("vgt: error: open %s failed", path);
        err = errno;
    }

    /* -domid means we want the vgt driver to free the vgt instance
     * of Domain domid.
     * */
    if (!err && fprintf(vgt_file, "%d\n", -xen_domid) < 0) {
        err = errno;
    }

    if (!err && fclose(vgt_file) != 0) {
        err = errno;
    }

    if (err) {
        qemu_log("vGT: %s: failed: errno=%d\n", __func__, err);
        exit(-1);
    }
}

static int pch_map_irq(PCIDevice *pci_dev, int irq_num)
{
    return irq_num;
}

static void vgt_pci_conf_init_from_host(PCIDevice *dev,
        uint32_t addr, int len)
{
    int ret;

    if (len > 4) {
        error_report("WARNIGN: length %x too large for config addr %x, ignore init",
                len, addr);
        return;
    }

    VGTHostDevice host_dev = {
        .addr.domain = 0,
        .addr.bus = pci_bus_num(dev->bus),
        .addr.slot = PCI_SLOT(dev->devfn),
        .addr.function = PCI_FUNC(dev->devfn),
    };

    /* FIXME: need a better scheme to grab the root complex. This
     * only for a single VM scenario.
     */
    vgt_host_device_get(&host_dev);
    ret = pread(host_dev.config_fd, dev->config + addr, len, addr);
    if (ret < len) {
        error_report("%s, read config addr %x, len %d failed.", __func__, addr, len);
        return;
    }
    vgt_host_device_put(&host_dev);
}

static int vgt_host_pci_get_byte(VGTHostDevice *host_dev,
                                  uint32_t addr, uint8_t *p)
{
    int ret;
    uint8_t buf;


    vgt_host_device_get(host_dev);
    ret = pread(host_dev->config_fd, &buf, 1, addr);
    if (ret < 1) {
        error_report("%s, failed.", __func__);
        return ret;
    }
    vgt_host_device_put(host_dev);

    *p = buf;
    return ret;
}

static void vgt_host_bridge_cap_init(PCIDevice *dev)
{
    assert(dev->devfn == 0x00);
    uint8_t cap_ptr = 0;

    VGTHostDevice host_dev = {
        .addr.domain = 0,
        .addr.bus = 0,
        .addr.slot = 0,
        .addr.function = 0,
    };

    vgt_host_pci_get_byte(&host_dev, PCI_CAPABILITY_LIST, &cap_ptr);
    while (cap_ptr !=0) {
        vgt_pci_conf_init_from_host(dev, cap_ptr, 4); /* capability */
        vgt_pci_conf_init_from_host(dev, cap_ptr + 4, 4); /* capability */
        vgt_pci_conf_init_from_host(dev, cap_ptr + 8, 4); /* capability */
        vgt_pci_conf_init_from_host(dev, cap_ptr + 12, 4); /* capability */
        //XEN_PT_LOG(pci_dev, "Add vgt host bridge capability: offset=0x%x, cap=0x%x\n", cap_ptr,
        //    pt_pci_host_read(0, PCI_SLOT(pci_dev->devfn), 0, cap_ptr, 1) & 0xFF );
        vgt_host_pci_get_byte(&host_dev, cap_ptr + 1, &cap_ptr);
    }
}

void vgt_bridge_pci_conf_init(PCIDevice *pci_dev)
{
    printf("vgt_bridge_pci_conf_init\n");
    printf("vendor id: %x\n", *(uint16_t *)((char *)pci_dev->config + 0x00));
    vgt_pci_conf_init_from_host(pci_dev, 0x00, 2); /* vendor id */
    printf("vendor id: %x\n", *(uint16_t *)((char *)pci_dev->config + 0x00));
    printf("device id: %x\n", *(uint16_t *)((char *)pci_dev->config + 0x02));
    vgt_pci_conf_init_from_host(pci_dev, 0x02, 2); /* device id */
    printf("device id: %x\n", *(uint16_t *)((char *)pci_dev->config + 0x02));
    vgt_pci_conf_init_from_host(pci_dev, 0x06, 2); /* status */
    vgt_pci_conf_init_from_host(pci_dev, 0x08, 2); /* revision id */
    vgt_pci_conf_init_from_host(pci_dev, 0x34, 1); /* capability */
    vgt_host_bridge_cap_init(pci_dev);
    vgt_pci_conf_init_from_host(pci_dev, 0x50, 2); /* SNB: processor graphics control register */
    vgt_pci_conf_init_from_host(pci_dev, 0x52, 2); /* processor graphics control register */
}

static void vgt_reset(DeviceState *dev)
{
}

static void vgt_cleanupfn(PCIDevice *dev)
{
    VGTVGAState *d = DO_UPCAST(VGTVGAState, dev, dev);

    if (d->instance_created) {
        destroy_vgt_instance();
    }
}

static int vgt_initfn(PCIDevice *dev)
{
    VGTVGAState *d = DO_UPCAST(VGTVGAState, dev, dev);

    DPRINTF("vgt_initfn\n");
    d->instance_created = TRUE;

    create_vgt_instance();
    return 0;
}

static int vgt_host_device_get(VGTHostDevice *dev)
{
    char name[PATH_MAX];
    int ret;

    snprintf(name, sizeof(name), "/sys/bus/pci/devices/%04x:%02x:%02x.%x/config",
             dev->addr.domain, dev->addr.bus, dev->addr.slot, dev->addr.function);
    dev->config_fd = open(name, O_RDONLY);
    if (dev->config_fd == -1) {
        error_report("vgt: open failed: %s\n", strerror(errno));
        return -1;
    }

    ret = pread(dev->config_fd, &dev->vendor_id, sizeof(dev->vendor_id), PCI_VENDOR_ID);
    if (ret < sizeof(dev->vendor_id)) {
        goto error;
    }
    ret = pread(dev->config_fd, &dev->device_id, sizeof(dev->device_id), PCI_DEVICE_ID);
    if (ret < sizeof(dev->device_id)) {
        goto error;
    }
    ret = pread(dev->config_fd, &dev->revision_id, sizeof(dev->revision_id), PCI_REVISION_ID);
    if (ret < sizeof(dev->revision_id)) {
        goto error;
    }
    ret = pread(dev->config_fd, &dev->class_dev, sizeof(dev->class_dev), PCI_CLASS_DEVICE);
    if (ret < sizeof(dev->class_dev)) {
        goto error;
    }
    DPRINTF("vendor: 0x%hx, device: 0x%hx, revision: 0x%hhx\n",
           dev->vendor_id, dev->device_id, dev->revision_id);

    return 0;

error:
    ret = ret < 0 ? -errno : -EFAULT;
    error_report("vgt: Failed to read device config space");
    return ret;
}

static void vgt_host_device_put(VGTHostDevice *dev)
{
    if (dev->config_fd >= 0) {
        close(dev->config_fd);
        dev->config_fd = -1;
    }
}

DeviceState *vgt_vga_init(PCIBus *pci_bus)
{
    PCIDevice *dev;
    PCIBridge *br;
    VGTHostDevice host_dev = {
        .addr.domain = 0,
        .addr.bus = 0,
        .addr.slot = 0x1f,
        .addr.function = 0,
    };

    if (vgt_host_device_get(&host_dev) < 0) {
        error_report("vgt: error: failed to get host PCI device");
        return NULL;
    }

    if (host_dev.vendor_id != PCI_VENDOR_ID_INTEL) {
        vgt_host_device_put(&host_dev);
        error_report("vgt: error: vgt-vga is only supported on Intel GPUs");
        return NULL;
    }

    vgt_host_device_put(&host_dev);

    dev = pci_create_multifunction(pci_bus, PCI_DEVFN(0x1f, 0), true,
                                   "vgt-isa");
    if (!dev) {
        error_report("vgt: error: vgt-isa not available");
        return NULL;
    }

    qdev_init_nofail(&dev->qdev);

    pci_config_set_vendor_id(dev->config, host_dev.vendor_id);
    pci_config_set_device_id(dev->config, host_dev.device_id);
    pci_config_set_revision(dev->config, host_dev.revision_id);
    pci_config_set_class(dev->config, host_dev.class_dev);
    br = PCI_BRIDGE(dev);
    pci_bridge_map_irq(br, "IGD Bridge",
                       pch_map_irq);

    printf("Create vgt ISA bridge successfully\n");

    dev = pci_create_multifunction(pci_bus, PCI_DEVFN(0x2, 0), true,
                                   "vgt-vga");
    if (!dev) {
        error_report("vgt: error: vgt-vga not available");
        return NULL;
    }

    qdev_init_nofail(&dev->qdev);
    printf("Create vgt VGA successfully\n");
    return DEVICE(dev);
}

static void vgt_class_initfn(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *ic = PCI_DEVICE_CLASS(klass);
    ic->init = vgt_initfn;
    dc->reset = vgt_reset;
    ic->exit = vgt_cleanupfn;
    dc->vmsd = &vmstate_vga_common;
}

static TypeInfo vgt_info = {
    .name          = "vgt-vga",
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(VGTVGAState),
    .class_init    = vgt_class_initfn,
};

static TypeInfo isa_info = {
    .name          = "vgt-isa",
    .parent        = TYPE_PCI_BRIDGE,
    .instance_size = sizeof(PCIBridge),
};

static void vgt_register_types(void)
{
    type_register_static(&vgt_info);
    type_register_static(&isa_info);
}

type_init(vgt_register_types)
