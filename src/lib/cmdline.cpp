#include <lib/assert.hpp>
#include <lib/cmdline.hpp>
#include <lib/string.hpp>
#include <mm/slab.hpp>
#include <util/kprint.hpp>

namespace NLib {

    void CmdlineParser::addpair(char *key, char *value) {
        struct pair *pair = new struct pair;
        assert(pair != NULL, "Failed to allocate memory for cmdline pair.\n");
        // Put values into pair.
        NLib::strncpy(pair->key, key, sizeof(pair->key) - 1);
        NLib::strncpy(pair->value, value, sizeof(pair->value) - 1);

        // Append pair to pair list.
        pair->next = this->pairlist;
        this->pairlist = pair;
    }

    void CmdlineParser::setup(char *cmd) {
        if (!cmd) {
            return;
        }

        char workingbuf[2048]; // XXX: Consider non-fixed size buffer?
        // Pad end with space for parsing.
        NUtil::snprintf(workingbuf, sizeof(workingbuf), "%s ", cmd);
        char *cmdline = &workingbuf[0];

        char namebuf[CmdlineParser::maxsize];
        NLib::memset(namebuf, 0, sizeof(namebuf));
        char valuebuf[CmdlineParser::maxsize];
        NLib::memset(valuebuf, 0, sizeof(valuebuf));

        size_t nameidx = 0;
        size_t valueidx = 0;

        enum {
            NAME,
            VALUE,
            QUOTEDVALUE
        };
        int state = NAME;

        while (*cmdline) {
            char c = *cmdline;

            switch (state) {
                case NAME: // Generic name parsing until we encounter value sets.
                    if (c == ' ') {
                        if (nameidx > 0) { // We have a name, but it's got no value. This is basically just a hecking "flag".
                            namebuf[nameidx] = '\0';
                            NUtil::snprintf(valuebuf, sizeof(valuebuf), "true");
                            this->addpair(namebuf, valuebuf);
                            nameidx = 0;
                            NLib::memset(namebuf, 0, sizeof(namebuf));
                        }
                        // Otherwise ignore extra spaces
                    } else if (c == '=') {
                        namebuf[nameidx] = '\0';
                        valueidx = 0;
                        NLib::memset(valuebuf, 0, sizeof(valuebuf));
                        state = VALUE; // Expect a value after this.
                    } else {
                        if (nameidx + 1 < sizeof(namebuf)) {
                            namebuf[nameidx++] = c;
                        }
                    }
                    break;

                case VALUE: // Accepts until space.
                    if (c == '"') {
                        valueidx = 0;
                        state = QUOTEDVALUE;
                    } else if (c == ' ') {
                        valuebuf[valueidx] = '\0';
                        this->addpair(namebuf, valuebuf);
                        nameidx = 0;
                        valueidx = 0;
                        NLib::memset(namebuf, 0, sizeof(namebuf));
                        NLib::memset(valuebuf, 0, sizeof(valuebuf));
                        state = NAME;
                    } else {
                        if (valueidx + 1 < sizeof(valuebuf)) {
                            valuebuf[valueidx++] = c;
                        }
                    }
                    break;

                case QUOTEDVALUE: // Accepts spaces until closing quote.
                    if (c == '"') {
                        valuebuf[valueidx] = '\0';
                        this->addpair(namebuf, valuebuf);
                        nameidx = 0;
                        valueidx = 0;
                        NLib::memset(namebuf, 0, sizeof(namebuf));
                        NLib::memset(valuebuf, 0, sizeof(valuebuf));
                        state = NAME;
                    } else {
                        if (valueidx + 1 < sizeof(valuebuf)) {
                            valuebuf[valueidx++] = c;
                        }
                    }
                    break;
            }

            cmdline++;
        }
        return;
    }

    char *CmdlineParser::get(const char *key) {
        if (!this->pairlist) {
            return NULL;
        }

        struct pair *pair = this->pairlist;

        while (pair) {
            // Simply just loop through every key/value pair, until we find the matching pair.
            if (!strncmp(key, pair->key, sizeof(pair->key) - 1)) {
                return pair->value;
            }
            pair = pair->next;
        }

        return NULL; // If we never found a matching pair, we return NULL.
    }
}
