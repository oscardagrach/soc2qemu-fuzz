/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * soc2qemu-fuzz MMIO input device, for QEMU trees based on qemu-libafl-bridge.
 *
 * Overlays a peripheral's MMIO window (addr, size) and answers every read in it with the
 * next bytes of the current fuzz input, little-endian. Writes are ignored. The input lives
 * in a small RAM window at `buf`, which the harness fills with write_phys_mem before each
 * run:
 *
 *   +0  magic  'S2QF' (0x46513253); anything else = disarmed, reads return 0
 *   +4  len    input length in bytes
 *   +8  pos    bytes consumed so far (the harness writes 0, the device advances it)
 *   +16 data
 *
 * Keeping the cursor in RAM makes the device stateless, so snapshots don't need to know
 * about it. A read past the end of the input asks libafl_qemu for a synchronous exit
 * (QemuExitReason::SyncExit), which the harness treats as a clean end of the run. Before the
 * harness arms it (boot up to the snapshot point), reads return 0 like an unimplemented
 * device.
 *
 *   -device soc2qemu-fuzz-mmio,addr=0x40024000,size=0x400,buf=0xf0000000
 *
 * Installed into the port's QEMU tree by soc2qemu-fuzz's fuzz.sh; not part of QEMU.
 */
#include "qemu/osdep.h"
#include "qemu/bswap.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "qapi/error.h"
#include "hw/qdev-properties.h"
#include "system/address-spaces.h"
#include "system/memory.h"
#include "hw/core/cpu.h"
#include "libafl/exit.h"

#define TYPE_SOC2QEMU_FUZZ_MMIO "soc2qemu-fuzz-mmio"
OBJECT_DECLARE_SIMPLE_TYPE(Soc2qemuFuzzMmioState, SOC2QEMU_FUZZ_MMIO)

#define FUZZ_MAGIC 0x46513253u /* "S2QF" */
#define HDR_SIZE 16

struct Soc2qemuFuzzMmioState {
    DeviceState parent_obj;

    MemoryRegion iomem;
    MemoryRegion buf_ram;
    uint64_t addr;
    uint64_t size;
    uint64_t buf;
    uint64_t buf_size;
};

static uint64_t fuzz_mmio_read(void *opaque, hwaddr offset, unsigned size)
{
    Soc2qemuFuzzMmioState *s = opaque;
    uint8_t *ram = memory_region_get_ram_ptr(&s->buf_ram);
    uint32_t len, pos;
    uint64_t value = 0;

    if (ldl_le_p(ram) != FUZZ_MAGIC) {
        return 0;
    }
    len = MIN(ldl_le_p(ram + 4), s->buf_size - HDR_SIZE);
    pos = ldl_le_p(ram + 8);
    if (pos + size > len) {
        if (current_cpu) {
            /* Does not return: unwinds to libafl_qemu's run loop. */
            libafl_exit_request_custom_insn(current_cpu, 0, LIBAFL_CUSTOM_INSN_UNDEFINED);
        }
        return 0;
    }
    for (unsigned i = 0; i < size; i++) {
        value |= (uint64_t)ram[HDR_SIZE + pos + i] << (8 * i);
    }
    stl_le_p(ram + 8, pos + size);
    return value;
}

static void fuzz_mmio_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
}

static const MemoryRegionOps fuzz_mmio_ops = {
    .read = fuzz_mmio_read,
    .write = fuzz_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 1,
    .valid.max_access_size = 8,
    .impl.min_access_size = 1,
    .impl.max_access_size = 8,
};

static void fuzz_mmio_realize(DeviceState *dev, Error **errp)
{
    Soc2qemuFuzzMmioState *s = SOC2QEMU_FUZZ_MMIO(dev);
    MemoryRegionSection sec;

    if (!s->size || s->buf_size <= HDR_SIZE) {
        error_setg(errp, "size and buf-size must be set (buf-size > %d)", HDR_SIZE);
        return;
    }
    /* The input window must not shadow anything the machine maps there. */
    sec = memory_region_find(get_system_memory(), s->buf, s->buf_size);
    if (sec.mr) {
        error_setg(errp, "buf 0x%" PRIx64 " overlaps %s; pick an unused address",
                   s->buf, memory_region_name(sec.mr));
        memory_region_unref(sec.mr);
        return;
    }

    memory_region_init_io(&s->iomem, OBJECT(dev), &fuzz_mmio_ops, s,
                          TYPE_SOC2QEMU_FUZZ_MMIO, s->size);
    /*
     * Ending a run unwinds out of fuzz_mmio_read, so the region's re-entrancy guard would stay
     * engaged and block every later access. The device does no DMA, so it can't re-enter.
     */
    s->iomem.disable_reentrancy_guard = true;
    if (!memory_region_init_ram(&s->buf_ram, OBJECT(dev), TYPE_SOC2QEMU_FUZZ_MMIO ".buf",
                                s->buf_size, errp)) {
        return;
    }
    /* Above the unimplemented-device stub (-1000) and the board's own model (0). */
    memory_region_add_subregion_overlap(get_system_memory(), s->addr, &s->iomem, 10);
    memory_region_add_subregion(get_system_memory(), s->buf, &s->buf_ram);
}

static const Property fuzz_mmio_props[] = {
    DEFINE_PROP_UINT64("addr", Soc2qemuFuzzMmioState, addr, 0),
    DEFINE_PROP_UINT64("size", Soc2qemuFuzzMmioState, size, 0),
    DEFINE_PROP_UINT64("buf", Soc2qemuFuzzMmioState, buf, 0),
    DEFINE_PROP_UINT64("buf-size", Soc2qemuFuzzMmioState, buf_size, 0x10000),
};

static void fuzz_mmio_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = fuzz_mmio_realize;
    device_class_set_props(dc, fuzz_mmio_props);
    dc->desc = "soc2qemu-fuzz MMIO input";
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo fuzz_mmio_info = {
    .name = TYPE_SOC2QEMU_FUZZ_MMIO,
    .parent = TYPE_DEVICE,
    .instance_size = sizeof(Soc2qemuFuzzMmioState),
    .class_init = fuzz_mmio_class_init,
};

static void fuzz_mmio_register_types(void)
{
    type_register_static(&fuzz_mmio_info);
}

type_init(fuzz_mmio_register_types)
