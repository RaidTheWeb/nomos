#ifdef __x86_64__
#include <arch/limine/requests.hpp>
#include <arch/x86_64/arch.hpp>
#include <arch/x86_64/cpu.hpp>
#include <arch/x86_64/vmm.hpp>
#endif

#include <dev/dev.hpp>
#include <dev/drivers/liminefb.hpp>
#include <fs/devfs.hpp>
#include <mm/ucopy.hpp>
#include <std/stddef.h>

namespace NDev {
    using namespace NFS;

    class LimineFBDriver : public DevDriver {
        private:
            static const uint64_t MAJOR = 29;
            static const uint64_t MINMINOR = 0;
            static const uint64_t MAXMINOR = 31;

            struct NDev::varscreeninfo *varinfos = NULL;
            struct NDev::fixscreeninfo *fixinfos = NULL;

            static struct limine_framebuffer *getfb(uint64_t minor) {
                size_t fbcount = NLimine::fbreq.response->framebuffer_count;
                if (minor >= fbcount) {
                    return NULL;
                }
                return NLimine::fbreq.response->framebuffers[minor];
            }

        public:
            LimineFBDriver(void) {

                if (NLimine::fbreq.response == NULL || NLimine::fbreq.response->framebuffer_count == 0) {
                    return;
                }

                size_t fbcount = NLimine::fbreq.response->framebuffer_count;

                this->fixinfos = new struct NDev::fixscreeninfo[fbcount];
                this->varinfos = new struct NDev::varscreeninfo[fbcount];

                for (size_t i = 0; i < fbcount; i++) {
                    struct limine_framebuffer *fb = NLimine::fbreq.response->framebuffers[i];

                    struct NDev::fixscreeninfo *fix = &this->fixinfos[i];
                    NLib::memset(fix, 0, sizeof(struct NDev::fixscreeninfo));
                    NUtil::snprintf(fix->id, sizeof(fix->id), "Limine FB %lu", i);

                    fix->smem_len = fb->pitch * fb->height;
                    fix->type = FB_TYPE_PACKED_PIXELS;
                    fix->visual = FB_VISUAL_TRUECOLOR;
                    fix->line_length = fb->pitch;
                    fix->mmio_len = fb->pitch * fb->height;

                    struct NDev::varscreeninfo *var = &this->varinfos[i];
                    NLib::memset(var, 0, sizeof(struct NDev::varscreeninfo));
                    var->xres = fb->width;
                    var->yres = fb->height;
                    var->xres_virtual = fb->width;
                    var->yres_virtual = fb->height;
                    var->bits_per_pixel = fb->bpp;

                    var->red.offset = fb->red_mask_shift;
                    var->red.length = fb->red_mask_size;
                    var->red.msb_right = 1;

                    var->green.offset = fb->green_mask_shift;
                    var->green.length = fb->green_mask_size;
                    var->green.msb_right = 1;

                    var->blue.offset = fb->blue_mask_shift;
                    var->blue.length = fb->blue_mask_size;
                    var->blue.msb_right = 1;

                    var->transp.msb_right = 1;

                    var->height = -1;
                    var->width = -1;

                    registry->add(new Device(DEVFS::makedev(MAJOR, i), this));

                    struct VFS::stat st = (struct VFS::stat) {
                        .st_mode = 0666 | VFS::S_IFCHR,
                        .st_rdev = DEVFS::makedev(MAJOR, i),
                        .st_size = fb->pitch * fb->height
                    };
                    st.st_blksize = 4096;
                    st.st_blocks = (st.st_size + 511) / 512;

                    VFS::INode *devnode;
                    char path[512];
                    NUtil::snprintf(path, sizeof(path), "/dev/fb%lu", i);
                    ssize_t res = VFS::vfs->create(path, &devnode, st);
                    assert(res == 0, "Failed to create framebuffer device node.");
                    devnode->unref();
                }
            }

            int ioctl(uint64_t dev, unsigned long request, uint64_t arg) {
                uint32_t minor = DEVFS::minor(dev);
                struct limine_framebuffer *fb = getfb(minor);
                if (!fb) {
                    return -ENODEV;
                }

                switch (request) {
                    case NDev::FBIOGET_VSCREENINFO: {
                        struct NDev::varscreeninfo *var = &this->varinfos[minor];
                        NMem::UserCopy::copyto((void *)arg, var, sizeof(struct NDev::varscreeninfo));
                        return 0;
                    }
                    case NDev::FBIOGET_FSCREENINFO: {
                        struct NDev::fixscreeninfo *fix = &this->fixinfos[minor];
                        NMem::UserCopy::copyto((void *)arg, fix, sizeof(struct NDev::fixscreeninfo));
                        return 0;
                    }
                    case NDev::FBIOBLANK:
                    case NDev::FBIOPUT_VSCREENINFO: {
                        return 0;
                    }
                    default:
                        return -EINVAL;
                }
            }

            ssize_t read(uint64_t dev, void *buf, size_t count, off_t offset, int fdflags) {
                uint32_t minor = DEVFS::minor(dev);
                struct limine_framebuffer *fb = getfb(minor);
                if (!fb) {
                    return -ENODEV;
                }

                if (offset >= (fb->pitch * fb->height)) {
                    return 0;
                }

                size_t toread = count;
                if (offset + toread > (fb->pitch * fb->height)) {
                    toread = (fb->pitch * fb->height) - offset;
                }

                NMem::UserCopy::copyto(buf, (void *)((uintptr_t)fb->address + offset), toread);
                return toread;
            }

            ssize_t write(uint64_t dev, const void *buf, size_t count, off_t offset, int fdflags) {
                uint32_t minor = DEVFS::minor(dev);
                struct limine_framebuffer *fb = getfb(minor);
                if (!fb) {
                    return -ENODEV;
                }

                if (offset >= (fb->pitch * fb->height)) {
                    return 0;
                }

                size_t towrite = count;
                if (offset + towrite > (fb->pitch * fb->height)) {
                    towrite = (fb->pitch * fb->height) - offset;
                }

                NMem::UserCopy::copyfrom((void *)((uintptr_t)fb->address + offset), buf, towrite);
                return towrite;
            }

            int mmap(uint64_t dev, void *addr, size_t count, size_t offset, uint64_t flags, int fdflags) {
                uint32_t minor = DEVFS::minor(dev);
                struct limine_framebuffer *fb = getfb(minor);
                if (!fb) {
                    return -ENODEV;
                }

                if (offset >= (fb->pitch * fb->height)) {
                    return -EINVAL;
                }

                size_t tomap = count;
                if (offset + tomap > (fb->pitch * fb->height)) {
                    tomap = (fb->pitch * fb->height) - offset;
                }

#ifdef __x86_64__
                uintptr_t phys = (uintptr_t)NArch::hhdmsub((void *)((uintptr_t)fb->address + offset));

                size_t vmmflags = 0 |
                    NArch::VMM::PRESENT |
                    NArch::VMM::USER |
                    ((flags & NMem::Virt::VIRT_RW) ? NArch::VMM::WRITEABLE : 0) |
                    NArch::VMM::DISABLECACHE;


                NSched::Process *proc = NArch::CPU::get()->currthread->process;
                if (!NArch::VMM::_maprange(proc->addrspace, (uintptr_t)addr, phys, vmmflags, tomap)) {
                    return -EFAULT;
                }
#endif

                return 0;
            }
    };

    static struct reginfo info  = {
        .name = "liminefb",
        .type = reginfo::GENERIC,
        .stage = reginfo::STAGE1,
        .match = { }
    };

    REGDRIVER(LimineFBDriver, &info);
}