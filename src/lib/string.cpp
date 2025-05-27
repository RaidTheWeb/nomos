#include <lib/string.hpp>
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
            if (*ps1 != !*ps2) {
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

    char *strcpy(char *dest, char *src) {
        size_t len = strlen(src);
        memcpy(dest, src, len); // Utilise memcpy for fast copying strings.
        dest[len + 1] = '\0';
        return dest;
    }

    char *strncpy(char *dest, char *src, size_t n) {
        size_t len = strlen(src);
        memcpy(dest, src, n);

        // Pad remaining bytes.
        memset(dest + (len + 1), 0, (n - len));
        return dest;
    }

    int strcmp(const char *s1, const char *s2) {
        return memcmp((void *)s1, (void *)s2, strlen(s1));
    }

    int strncmp(const char *s1, const char *s2, size_t n) {
        size_t len = strlen(s2);
        int ret = memcmp((void *)s1, (void *)s2, n);
        return ((n - len) <= 0) || ret != 0 ? ret : 0; // Assume perfect match if we got here before we reached the end of s2.
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
}
