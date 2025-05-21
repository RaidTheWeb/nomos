#include <lib/cmdline.hpp>
#include <util/kprint.hpp>

namespace NLib {


    CmdlineParser::CmdlineParser(char *cmd) {
        NUtil::printf("Parsing \"%s\".\n", cmd);

        char workingbuf[1024];
        // Pad end with space for parsing.
        NUtil::snprintf(workingbuf, sizeof(workingbuf), "%s ", cmd);
        char *cmdline = &workingbuf[0];


        char namebuf[64];
        char valuebuf[64];
        size_t writeidx = 0;

        bool parsingtext = false;
        while (*cmdline) {
            NUtil::printf("parse '%c'.\n", *cmdline);
            switch (*cmdline) {
                case '"': {
                    if (parsingtext) {
                        NUtil::printf("End parsing text values.\n");
                        valuebuf[writeidx] = '\0';
                        writeidx = 0;
                        parsingtext = false;
                        // String completed, set value.
                        goto skip;
                    } else {
                        NUtil::printf("Start parsing text values.\n");
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
                        NUtil::printf("break off.\n");
                        // This means that we break off the variable name, with no value set.
                        NUtil::sprintf(valuebuf, "true");
                        namebuf[writeidx] = '\0';
                        goto skip;
                        break;
                    }
                    // Fall through on parsing text.
                }
                default:
                    if (parsingtext) {
                        NUtil::printf("Add '%c' to value buffer.\n", *cmdline);
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
skip:

        NUtil::printf("%s=\"%s\" all is well!\n", namebuf, valuebuf);
        return;
    }
}
