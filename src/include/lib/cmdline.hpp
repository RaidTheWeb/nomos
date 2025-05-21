#ifndef _LIB__CMDLINE_HPP
#define _LIB__CMDLINE_HPP

namespace NLib {
    class CmdlineParser {
        private:
        public:
            CmdlineParser(char *cmdline);

            char *get(const char *key);
    };
}

#endif
