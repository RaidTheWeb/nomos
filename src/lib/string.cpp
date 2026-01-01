#include <lib/string.hpp>
#include <mm/slab.hpp>
#include <util/kprint.hpp>

namespace NLib {
    void *memcpy(void *dest, void *src, size_t n) {
        uint8_t *pdest = (uint8_t *)dest;
        uint8_t *psrc = (uint8_t *)src;

        // Try to copy big bits of data if possible.
        while (n >= sizeof(size_t)) {
            *(size_t *)pdest = *(size_t *)psrc;
            pdest += sizeof(size_t);
            psrc += sizeof(size_t);
            n -= sizeof(size_t);
        }

        // Copy in bytes for the rest.
        while (n--) {
            *pdest++ = *psrc++;
        }

        return dest;
    }

    void *memset(void *dest, int c, size_t n) {
        uint8_t *pdest = (uint8_t *)dest;

        if (n >= sizeof(size_t)) {
            size_t word = 0;
            // Try to fill a big bit of data with c.
            for (size_t i = 0; i < sizeof(size_t); i++) {
                word = (word << 8) | (uint8_t)c;
            }

            while ((uintptr_t)pdest % sizeof(size_t) != 0 && n) {
                *pdest = (uint8_t)c;
                n--;
                pdest++;
            }

            size_t *sdest = (size_t *)pdest;
            while (n >= sizeof(size_t)) {
                *sdest = word;
                n -= sizeof(size_t);
                sdest++;
            }

            pdest = (uint8_t *)sdest;
        }

        // Copy in bytes for the rest.
        while (n--) {
            *pdest++ = c;
        }
        return dest;
    }

    void *memmove(void *dest, void *src, size_t n) {
        uint8_t *pdest = (uint8_t *)dest;
        uint8_t *psrc = (uint8_t *)src;

        if ((uintptr_t)pdest < (uintptr_t)psrc) {
            return memcpy(dest, src, n);
        } else if ((uintptr_t)pdest > (uintptr_t)psrc) {
            while (n--) { // Start from size, work backwards.
                pdest[n] = psrc[n]; // Reverse copy.
            }
        }

        return dest;
    }

    int memcmp(void *s1, void *s2, size_t n) {
        uint8_t *ps1 = (uint8_t *)s1;
        uint8_t *ps2 = (uint8_t *)s2;

        while (n--) {
            if (*ps1 != *ps2) {
                return *ps1 - *ps2; // Match failed, return difference between differing bytes.
            }
            ps1++;
            ps2++;
        }

        return 0; // Perfect match.
    }

    size_t strlen(const char *str) {
        char *pstr = (char *)str;
        while (*pstr) {
            pstr++;
        }
        return pstr - str; // This is neat: we can return the difference between pointers to find the length of the string, instead of incrementing a variable or whatever.
    }

    size_t strnlen(const char *str, size_t n) {
        char *pstr = (char *)str;
        while(n-- && *pstr) { // Same as strlen, but with a check for the max length.
            pstr++;
        }
        return pstr - str;
    }

    char *strcpy(char *dest, char *src) {
        size_t len = strlen(src);
        memcpy(dest, src, len); // Utilise memcpy for fast copying strings.
        dest[len] = '\0';
        return dest;
    }

    char *strncpy(char *dest, char *src, size_t n) {
        size_t len = strlen(src);
        memcpy(dest, src, n);

        // Pad remaining bytes.
        if (n > len) {
            memset(dest + len, 0, (n - len));
        }
        return dest;
    }

    int strcmp(const char *s1, const char *s2) {
        size_t len1 = strlen(s1);
        size_t len2 = strlen(s2);
        size_t cmplen = len1 < len2 ? len1 : len2;

        int ret = memcmp((void *)s1, (void *)s2, cmplen);

        if (!ret) {
            // Handle length differences. These count as inequalities.
            if (len1 < len2) {
                return -1;
            } else if (len1 > len2) {
                return 1;
            }
        }

        return ret;
    }

    int strncmp(const char *s1, const char *s2, size_t n) {
        size_t len1 = strnlen(s1, n);
        size_t len2 = strnlen(s2, n);
        size_t cmplen = len1 < len2 ? len1 : len2; // Find minimum of the two.

        int ret = memcmp((void *)s1, (void *)s2, cmplen); // Compare against minimum string length.

        if (!ret) {
            if (len1 < len2) {
                return -1;
            } else if (len1 > len2) {
                return 1;
            }
        }

        return ret;
    }

    char *strchr(char *str, int c) {
        while (*str != c) { // Loop until we find it.
            if (*str) {
                return NULL; // Couldn't find it.
            }
            str++;
        }
        return str;
    }

    char *strstr(const char *haystack, const char *needle) {
        if (!*needle) { // First character is zero.
            return (char *)haystack; // Implicit start on '\0'.
        }
        while (*haystack) {
            if (*haystack == *needle) { // We may have a match here...
                char *phaystack = (char *)haystack;
                char *pneedle = (char *)needle;

                // Iterate over the next characters to see if we can find a full match.
                while (*phaystack && *pneedle) {
                    if (*phaystack != *pneedle) { // If no match, break.
                        break;
                    }

                    // Move to next character.
                    phaystack++;
                    pneedle++;
                }

                if (!*pneedle) { // If needle is NULL, we managed to get to the end and have a full match!
                    return (char *)haystack; // This *current* location in the haystack.
                }
            }

            haystack++;
        }

        return NULL; // No match.
    }

    char *strtrim(char *str) {
        if (!str) {
            return NULL;
        }

        char *end = str + strlen(str) - 1; // Get reference to last character.
        while (end >= str && *end == ' ') { // For as long as we still have whitespace.
            end--; // Trailing end removal.
        }
        *(end + 1) = '\0'; // NULL terminate.

        char *start = str;
        while (start && *start == ' ') { // For as long as we still have whitespace.
            start++; // Leading end removal.
        }
        memmove(str, start, strlen(start) + 1); // Move start backwards in memory, this will have included our previous trailing edits, so it'll apply them too.

        return str;
    }

    char *strdup(const char *str) {
        size_t len = strlen(str);
        char *dup = new char[len + 1];
        strncpy(dup, (char *)str, len);
        dup[len] = '\0';
        return dup;
    }

    char *strcat(char *dest, char *src) {
        char *ptr = dest + strlen(dest);
        while (*src) {
            *ptr++ = *src++;
        }
        *ptr = '\0';
        return dest;
    }

    char *strndup(const char *str, size_t n) {
        size_t len = strnlen(str, n);

        char *dup = new char[len + 1];
        strncpy(dup, (char *)str, len);
        dup[len] = '\0';
        return dup;
    }

    int atoi(const char *str) {
        int result = 0;
        bool negative = false;

        while (*str == ' ') {
            str++;
        }

        if (*str == '-') {
            negative = true;
            str++;
        } else if (*str == '+') {
            str++;
        }

        while (*str >= '0' && *str <= '9') {
            result = result * 10 + (*str - '0');
            str++;
        }

        return negative ? -result : result;
    }

    int itoa(int value, char *str, int base) {
        if (base < 2 || base > 36) {
            *str = '\0';
            return 0;
        }

        char *ptr = str, *ptr1 = str, tmp_char;
        int tmp_value;
        bool negative = false;

        if (value < 0 && base == 10) {
            negative = true;
            value = -value;
        }

        do {
            tmp_value = value;
            value /= base;
            // It's pretty neat that we can do this.
            *ptr++ = "0123456789abcdefghijklmnopqrstuvwxyz"[tmp_value - value * base];
        } while (value);

        if (negative) {
            *ptr++ = '-';
        }
        *ptr-- = '\0';

        while (ptr1 < ptr) {
            tmp_char = *ptr;
            *ptr-- = *ptr1;
            *ptr1++ = tmp_char;
        }

        return ptr - str + 1;
    }
}
