#ifndef _UTIL__KMARKER_HPP
#define _UTIL__KMARKER_HPP

#include <util/kprint.hpp>

namespace NUtil {
    // Utility for stupid-simple printf debugging. Simply notes that a particular marker has been reached. Good for tracing without GDB (ie. real hardware).

    #define MARKER ({ \
        NUtil::printf("Reached marker in %s() at %s:%d.\n", __FUNCTION__, __FILE__, __LINE__); \
    })
}

#endif
