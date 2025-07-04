#ifndef _DEBUG__UBSAN_HPP
#define _DEBUG__UBSAN_HPP

#include <stddef.h>
#include <stdint.h>

namespace NDebug {
    namespace UBSan {
        struct sourceloc {
            const char *file;
            uint32_t line;
            uint32_t col;
        };

        struct typedesc {
            uint16_t kind;
            uint16_t info;
            char name[];
        };

        struct typemismatch {
            struct sourceloc loc;
            struct typedesc *type;
            uintptr_t align;
            uint8_t kind;
        };

        struct typemismatchv1 {
            struct sourceloc loc;
            struct typedesc *type;
            uint8_t align;
            uint8_t kind;
        };

        struct pointeroverflow {
            struct sourceloc loc;
        };

        struct outofbounds {
            struct sourceloc loc;
            struct typedesc *array;
            struct typedesc *index;
        };

        struct shiftoutofbounds {
            struct sourceloc loc;
            struct typedesc *lhs;
            struct typedesc *rhs;
        };

        struct overflow {
            struct sourceloc loc;
            struct typedesc *type;
        };

        struct invalidvalue {
            struct sourceloc loc;
            struct typedesc *type;
        };

        struct nonnullarg {
            struct sourceloc loc;
            struct sourceloc attrloc;
            int argidx;
        };

        struct unreachable {
            struct sourceloc loc;
        };
    }
}

#endif
