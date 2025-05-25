#ifndef _LIB__CMDLINE_HPP
#define _LIB__CMDLINE_HPP

#include <stddef.h>

namespace NLib {
    class CmdlineParser {
        private:
            struct pair {
                char key[64];
                char value[64];
                struct pair *next;
            };

            struct pair *pairlist;

            void addpair(char *key, char *value);

        public:
            CmdlineParser(void) { };

            static const size_t maxsize = 64;

            void setup(char *cmdline);

            char *get(const char *key);
    };
}

#endif
