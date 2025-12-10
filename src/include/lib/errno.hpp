#ifndef _LIB__ERRNO_HPP
#define _LIB__ERRNO_HPP

#define EPERM           1
#define ENOENT          2
#define ESRCH           3
#define EINTR           4
#define EIO             5
#define ENXIO           6
#define E2BIG           7
#define ENOEXEC         8
#define EBADF           9
#define ECHILD          10
#define EAGAIN          11
#define ENOMEM          12
#define EACCES          13
#define EFAULT          14
#define ENOTBLK         15
#define EBUSY           16
#define EEXIST          17
#define EXDEV           18
#define ENODEV          19
#define ENOTDIR         20
#define EISDIR          21
#define EINVAL          22
#define ENFILE          23
#define EMFILE          24
#define ENOTTY          25
#define ETXTBSY         26
#define EFBIG           27
#define ENOSPC          28
#define ESPIPE          29
#define EROFS           30
#define EMLINK          31
#define EPIPE           32
#define EDOM            33
#define ERANGE          34
#define EDEADLK         35
#define ENAMETOOLONG    36
#define ENOLCK          37
#define ENOSYS          38
#define ENOTEMPTY       39
#define ELOOP           40
#define ENOMSG          42
#define EIDRM           43
#define EOVERFLOW       75

constexpr const char *strerror(int errnum) {
    switch (errnum) {
        case 0: return "No error";
        case EPERM: return "Operation not permitted";
        case ENOENT: return "No such file or directory";
        case ESRCH: return "No such process";
        case EINTR: return "Interrupted system call";
        case EIO: return "I/O error";
        case ENXIO: return "No such device or address";
        case E2BIG: return "Argument list too long";
        case ENOEXEC: return "Exec format error";
        case EBADF: return "Bad file number";
        case ECHILD: return "No child processes";
        case EAGAIN: return "Try again";
        case ENOMEM: return "Out of memory";
        case EACCES: return "Permission denied";
        case EFAULT: return "Bad address";
        case ENOTBLK: return "Block device required";
        case EBUSY: return "Device or resource busy";
        case EEXIST: return "File exists";
        case EXDEV: return "Cross-device link";
        case ENODEV: return "No such device";
        case ENOTDIR: return "Not a directory";
        case EISDIR: return "Is a directory";
        case EINVAL: return "Invalid argument";
        case ENFILE: return "File table overflow";
        case EMFILE: return "Too many open files";
        case ENOTTY: return "Not a TTY";
        case ETXTBSY: return "Text file busy";
        case EFBIG: return "File too large";
        case ENOSPC: return "No space left on device";
        case ESPIPE: return "Illegal seek";
        case EROFS: return "Read-only file system";
        case EMLINK: return "Too many links";
        case EPIPE: return "Broken pipe";
        case EDOM: return "Math argument out of domain of func";
        case ERANGE: return "Math result not representable";
        case EDEADLK: return "Resource deadlock would occur";
        case ENAMETOOLONG: return "File name too long";
        case ENOLCK: return "No record locks available";
        case ENOSYS: return "Function not implemented";
        case ENOTEMPTY: return "Directory not empty";
        case ELOOP: return "Too many symbolic links encountered";
        case ENOMSG: return "No message of desired type";
        case EIDRM: return "Identifier removed";
        case EOVERFLOW: return "Value too large for defined data type";
        default: return "Unknown error";
    }
}

#endif
