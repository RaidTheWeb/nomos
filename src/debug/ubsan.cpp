#ifdef __x86_64__
#include <arch/x86_64/io.hpp>
#include <arch/x86_64/panic.hpp>
#endif
#include <debug/ubsan.hpp>
#include <util/kprint.hpp>

namespace NDebug {
    namespace UBSan {

        // UBSan runtime debug stubs.

        static inline bool isaligned(uintptr_t ptr, uintptr_t align) {
            return !(ptr & (align - 1));
        }

        static const char *kinds[] = {
            "load of",
            "store to",
            "reference binding to",
            "member access within",
            "member call on",
            "constructor call on",
            "downcast of",
            "downcast of",
            "upcast of",
            "cast to virtual base of"
        };

        void handleviolation(const char *violation, struct sourceloc *loc) {
            // char errbuffer[2048];
            // NUtil::snprintf(errbuffer, sizeof(errbuffer), "UBSan violation (%s) at %s:%d failed:\n", violation, loc->file, loc->line);
            // NArch::panic(errbuffer);
            NUtil::printf("UBSan violation (%s) at %s:%d failed:\n", violation, loc->file, loc->line);
            for (;;) {
                asm volatile("hlt");
            }
        }

        extern "C" void __ubsan_handle_type_mismatch(struct typemismatch *info, uintptr_t ptr) {
            struct sourceloc *loc = &info->loc;

            char violation[256];
            if (ptr == 0) {
                NUtil::snprintf(violation, sizeof(violation), "NULL pointer access");
            } else if (info->align != 0 && isaligned(ptr, info->align)) {
                NUtil::snprintf(violation, sizeof(violation), "Unaligned memory access");
            } else {
                NUtil::snprintf(violation, sizeof(violation), "Insufficient size in %s of address %p with insufficient space for %s", kinds[info->kind], (void *)ptr, info->type->name);
            }

            handleviolation(violation, loc);
        }

        extern "C" void __ubsan_handle_type_mismatch_v1(struct typemismatchv1 *info, uintptr_t ptr) {
            struct sourceloc *loc = &info->loc;

            uintptr_t alignment = (uintptr_t) 1ul << info->align;
            char violation[256];
            if (ptr == 0) {
                NUtil::snprintf(violation, sizeof(violation), "NULL pointer access");
            } else if (alignment != 0 && isaligned(ptr, alignment)) {
                NUtil::snprintf(violation, sizeof(violation), "Unaligned memory access");
            } else {
                NUtil::snprintf(violation, sizeof(violation), "Insufficient size in %s of address %p with insufficient space for %s", kinds[info->kind], (void *)ptr, info->type->name);
            }

            handleviolation(violation, loc);

        }

        extern "C" void __ubsan_handle_pointer_overflow(struct pointeroverflow *info, uintptr_t ptr, uintptr_t result) {
            (void)ptr;
            (void)result;
            handleviolation("Pointer overflow", &info->loc);
        }

        extern "C" void __ubsan_handle_out_of_bounds(struct outofbounds *info, uintptr_t index) {
            (void)index;
            handleviolation("Out of bounds", &info->loc);
        }

        extern "C" void __ubsan_handle_shift_out_of_bounds(struct shiftoutofbounds *info, uintptr_t lhs, uintptr_t rhs) {
            (void)lhs;
            (void)rhs;
            handleviolation("Shift out of bounds", &info->loc);
        }

        extern "C" void __ubsan_handle_add_overflow(struct overflow *info, uintptr_t lhs, uintptr_t rhs) {
            (void)lhs;
            (void)rhs;
            handleviolation("Addition overflow", &info->loc);
        }

        extern "C" void __ubsan_handle_sub_overflow(struct overflow *info, uintptr_t lhs, uintptr_t rhs) {
            (void)lhs;
            (void)rhs;
            handleviolation("Subtraction overflow", &info->loc);
        }

        extern "C" void __ubsan_handle_mul_overflow(struct overflow *info, uintptr_t lhs, uintptr_t rhs) {
            (void)lhs;
            (void)rhs;
            handleviolation("Multiplication overflow", &info->loc);
        }

        extern "C" void __ubsan_handle_negate_overflow(struct overflow *info, uintptr_t lhs, uintptr_t rhs) {
            (void)lhs;
            (void)rhs;
            handleviolation("Negation overflow", &info->loc);
        }

        extern "C" void __ubsan_handle_divrem_overflow(struct overflow *info, uintptr_t lhs, uintptr_t rhs) {
            (void)lhs;
            (void)rhs;
            handleviolation("Division remainder overflow", &info->loc);
        }

        extern "C" void __ubsan_handle_load_invalid_value(struct invalidvalue *info, uintptr_t value) {
            (void)value;
            handleviolation("Invalid value load", &info->loc);
        }

        extern "C" void __ubsan_handle_nonnull_arg(struct nonnullarg *info, intptr_t idx) {
            (void)idx;
            handleviolation("Null argument", &info->loc);
        }
    }
}
