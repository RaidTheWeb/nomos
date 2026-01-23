#ifndef _DEV__DRIVERS__LIMINEFB_HPP
#define _DEV__DRIVERS__LIMINEFB_HPP

#include <stdint.h>
#include <std/stddef.h>

namespace NDev {
    struct bitfield {
        uint32_t offset;
        uint32_t length;
        uint32_t msb_right;
    };

    struct varscreeninfo {
        uint32_t xres;
        uint32_t yres;
        uint32_t xres_virtual;
        uint32_t yres_virtual;
        uint32_t xoffset;
        uint32_t yoffset;
        uint32_t bits_per_pixel;
        uint32_t grayscale;
        struct bitfield red;
        struct bitfield green;
        struct bitfield blue;
        struct bitfield transp;
        uint32_t nonstd;
        uint32_t activate;
        uint32_t height;
        uint32_t width;
        uint32_t accel_flags;
        uint32_t pixclock;
        uint32_t left_margin;
        uint32_t right_margin;
        uint32_t upper_margin;
        uint32_t lower_margin;
        uint32_t hsync_len;
        uint32_t vsync_len;
        uint32_t sync;
        uint32_t vmode;
        uint32_t rotate;
        uint32_t colourspace;
        uint32_t reserved[4];
    };

    struct fixscreeninfo {
        char id[16];
        uint64_t smem_start;
        uint32_t smem_len;
        uint32_t type;
        uint32_t type_aux;
        uint32_t visual;
        uint16_t xpanstep;
        uint16_t ypanstep;
        uint16_t ywrapstep;
        uint32_t line_length;
        uint32_t mmio_start;
        uint32_t mmio_len;
        uint32_t accel;
        uint16_t capabilities;
        uint16_t reserved[2];
    };

    enum fbtype {
        FB_TYPE_PACKED_PIXELS = 0,
        FB_TYPE_PLANES = 1,
        FB_TYPE_INTERLEAVED_PLANES = 2,
        FB_TYPE_TEXT = 3,
        FB_TYPE_VGA_PLANES = 4,
        FB_TYPE_FOURCC = 5
    };

    enum fbvisual {
        FB_VISUAL_MONO01 = 0,
        FB_VISUAL_MONO10 = 1,
        FB_VISUAL_TRUECOLOR = 2,
        FB_VISUAL_PSEUDOCOLOR = 3,
        FB_VISUAL_DIRECTCOLOR = 4,
        FB_VISUAL_STATIC_PSEUDOCOLOR = 5,
        FB_VISUAL_FOURCC = 6
    };

    enum fbioctl {
        FBIOGET_VSCREENINFO = 0x4600,
        FBIOPUT_VSCREENINFO = 0x4601,
        FBIOGET_FSCREENINFO = 0x4602,

        FBIOBLANK = 0x4611
    };
}

#endif