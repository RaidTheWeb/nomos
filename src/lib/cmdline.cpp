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
        char workingbuf[1024];
        // Pad end with space for parsing.
        NUtil::snprintf(workingbuf, sizeof(workingbuf), "%s ", cmd);
        char *cmdline = &workingbuf[0];


        char namebuf[CmdlineParser::maxsize];
        NLib::memset(namebuf, 0, sizeof(namebuf));
        char valuebuf[CmdlineParser::maxsize];
        NLib::memset(valuebuf, 0, sizeof(valuebuf));

        size_t writeidx = 0;

        bool parsingtext = false;
        while (*cmdline && writeidx < CmdlineParser::maxsize) {
            switch (*cmdline) {
                case '"': {
                    if (parsingtext) {
                        valuebuf[writeidx] = '\0';
                        writeidx = 0;
                        parsingtext = false;
                        // String completed, set value.
                        this->addpair(namebuf, valuebuf);
                    } else {

                        namebuf[writeidx] = '\0';
                        // Start parsing text.
                        writeidx = 0;
                        parsingtext = true;
                    }
                    break;
                }
                case '=': {
                    // Set value.
                    break;
                }
                case ' ': {
                    if (!parsingtext) {
                        if (writeidx > 0) {// Only break off if it's at least one character.
                            // This means that we break off the variable name, with no value set.
                            NUtil::sprintf(valuebuf, "true");
                            namebuf[writeidx] = '\0';
                            this->addpair(namebuf, valuebuf);
                            writeidx = 0; // Reset write index, so we can start on the next argument.
                        }
                        break; // In both cases, move on.
                    }
                    // Fall through on parsing text.
                }
                default:
                    if (parsingtext) {
                        // Add to value.
                        valuebuf[writeidx++] = *cmdline;
                    } else {
                        // Start parsing variable name.
                        namebuf[writeidx++] = *cmdline;
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
