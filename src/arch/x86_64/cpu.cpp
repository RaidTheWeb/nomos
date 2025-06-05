#include <arch/x86_64/cpu.hpp>

namespace NArch {
    namespace CPU {

        static CPU::CPUInst bspinst = CPUInst();

        CPUInst *getbsp(void) {
            return &bspinst;
        }

        void init(void) {

        }
    }
}
