#ifndef _LIB__BITMAP_HPP
#define _LIB__BITMAP_HPP

#include <lib/string.hpp>
#include <mm/slab.hpp>
#include <stddef.h>
#include <stdint.h>
#include <util/kprint.hpp>

namespace NLib {

    class Bitmap {
        private:
            static const size_t BITSPERWORD = 64;

            uint64_t *data;
            size_t size;

        public:
            Bitmap(size_t bits = 0) {
                this->data = NULL;
                this->size = 0;
                this->resize(bits);
            }

            ~Bitmap(void) {
                if (this->data) {
                    delete[] this->data;
                }
            }

            bool resize(size_t newsize) {
                if (this->size == newsize) {
                    return true;
                }

                size_t oldfullsize = (this->size + BITSPERWORD - 1) / BITSPERWORD;
                size_t newfullsize = (newsize + BITSPERWORD - 1) / BITSPERWORD;
                this->data = (uint64_t *)NMem::allocator.realloc(this->data, sizeof(uint64_t) * newfullsize);
                if (oldfullsize < newfullsize) {
                    // Clear newly allocated bits (ensures zero).
                    NLib::memset((void *)((uintptr_t)this->data + oldfullsize), 0, newfullsize - oldfullsize);
                }
                if (!this->data) {
                    return false;
                }

                this->size = newsize;
                return true;
            }

            void set(size_t idx) {
                if (idx >= this->size) {
                    return;
                }

                size_t word = idx / BITSPERWORD;
                size_t bit = idx % BITSPERWORD;

                this->data[word] |= (1ull << bit);
            }

            void clear(size_t idx) {
                if (idx >= this->size) {
                    return;
                }

                size_t word = idx / BITSPERWORD;
                size_t bit = idx % BITSPERWORD;
                this->data[word] &= ~(1ull << bit);
            }

            bool test(size_t idx) {
                if (idx >= this->size) {
                    return false;
                }

                size_t word = idx / BITSPERWORD;
                size_t bit = idx % BITSPERWORD;
                return (this->data[word] & (1ull << bit)) != 0;
            }

            size_t getsize(void) {
                return this->size;
            }

            ssize_t findfirst(void) {
                size_t wordcount = (this->size + BITSPERWORD - 1) / BITSPERWORD;
                for (size_t word = 0; word < wordcount; word++) {
                    uint64_t val = this->data[word];
                    if (val != ~0ull) {
                        const size_t maxbit = (word == wordcount - 1) ? this->size % BITSPERWORD : BITSPERWORD;

                        for (size_t bit = 0; bit < maxbit; bit++) {
                            if (!(val & (1ull << bit))) {
                                return word * BITSPERWORD + bit;
                            }
                        }
                    }
                }
                return -1;
            }
    };
}

#endif
