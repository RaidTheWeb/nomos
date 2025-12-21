#ifndef _FS__EXT4__DEFS_HPP
#define _FS__EXT4__DEFS_HPP

#include <stdint.h>

namespace NFS {
    namespace Ext4FS {

        struct superblock {
            uint32_t inodecount; // Total number of inodes.
            uint32_t blkcntlo; // Total number of blocks.
            uint32_t rsvdblkcntlo; // Number of reserved blocks.
            uint32_t freeblkcntlo; // Number of free blocks.
            uint32_t freeinodecnt; // Number of free inodes.
            uint32_t firstdatablk; // First data block.
            uint32_t logblocksize; // Block size = 1024 << logblocksize.
            uint32_t logclustersize; // Cluster size = 1024 << logclustersize.
            uint32_t blockspergroup; // Number of blocks per group.
            uint32_t clusterspergroup; // Number of clusters per group.
            uint32_t inodespergroup; // Number of inodes per group.
            uint32_t mtime; // Mount time.
            uint32_t wtime; // Write time.
            uint16_t mountcount; // Number of mounts since last check.
            uint16_t maxmountcount; // Max number of mounts before a check.
            uint16_t magic; // EXT4 magic number.
            uint16_t state; // File system state.
            uint16_t errors; // Behaviour when detecting errors.
            uint16_t minorrevlevel; // Minor revision level.
            uint32_t lastcheck; // Time of last check.
            uint32_t checkinterval; // Max time between checks.
            uint32_t creatoros; // OS that created the filesystem.
            uint32_t revlevel; // Revision level.
            uint16_t defresuid; // Default reserved UID.
            uint16_t defresgid; // Default reserved GID.

            // EXT4 fields.
            uint32_t firstinodenr; // First non-reserved inode.
            uint16_t inodesize; // Size of each inode structure.
            uint16_t blockgroupnr; // Block group number of this superblock.
            uint32_t featcompat; // Compatible feature set.
            uint32_t featincompat; // Incompatible feature set.
            uint32_t featrocompat; // Read-only compatible feature set.
            uint8_t uuid[16]; // 128-bit volume UUID.
            char volumename[16]; // Volume name.
            char lastmounted[64]; // Directory where last mounted.
            uint32_t algobmap; // For compression.

            // Performance hints.
            uint8_t preallocblks; // Number of blocks to preallocate for files.
            uint8_t preallocdirblks; // Number of blocks to preallocate for directories
            uint16_t unused1;

            // Journaling support.
            uint8_t journaluuid[16]; // UUID of journal superblock.
            uint32_t journalinodenum; // Inode number of journal file.
            uint32_t journaldev; // Device number of journal file if on external device.
            uint32_t lastorphan; // Start of list of orphaned inodes to delete on recovery.

            // Directory indexing support.
            uint32_t hashseed[4]; // HTREE hash seed.
            uint8_t defhashversion; // Default hash version to use.
            uint8_t jnlbackuptype; // Journal backup type.
            uint16_t descsize; // Size of group descriptor.

            // Other options.
            uint32_t defaultmountopts; // Default mount options.
            uint32_t firstmetabg; // First metablock block group.
            uint32_t creationtime; // File system creation time.
            uint32_t journalblks[17]; // Backup copies of the journal superblock.

            // 64-bit support.
            uint32_t blkcnthi; // Blocks count high 32 bits.
            uint32_t rsvdblkcnthi; // Reserved blocks count high 32 bits.
            uint32_t freeblkcnthi; // Free blocks count high 32 bits.
            uint16_t minextraisize; // All inodes have at least this much space.
            uint16_t wantextraisize; // New inodes should reserve this much space.
            uint32_t mflags; // Miscellaneous flags.
            uint16_t raidstride; // RAID stride (blocks read/written before moving to next disk).
            uint16_t mmpinterval; // Multi-mount protection check interval in seconds.
            uint64_t mmpblock; // Block number for multi-mount protection data.
            uint32_t raidstripewidth; // RAID stripe width (blocks on all data disks).
            uint8_t loggroupsperflex; // Number of block groups per flex group.
            uint8_t csumtype; // Checksum type.
            uint8_t encryptlevel; // Encryption level.
            uint8_t rsvdpad; // Padding to 32-bit alignment.
            uint64_t kbyteswritten; // Number of kilobytes written to this FS.
            uint32_t snapshotinodenum; // Inode number of active snapshot.
            uint32_t snapshotid; // Sequential ID of active snapshot.
            uint64_t snapshotrsvdblocks; // Reserved blocks for active snapshot.
            uint32_t snapshotlist; // Inode number of the head of the snapshot list.

            uint32_t errorcount; // Number of errors seen.

            uint32_t firsterrortime; // Time of first error.
            uint32_t firsterrinode; // Inode involved in first error.
            uint64_t firsterrblk; // Block involved in first error.
            uint8_t firsterrfunc[32]; // Function name where the error occurred.
            uint32_t firsterrline; // Line number where error occurred.

            uint32_t lasterrortime; // Time of last error.
            uint32_t lasterrinode; // Inode involved in last error.
            uint32_t lasterrline; // Line number where error occurred.
            uint64_t lasterrblk; // Block involved in last error.
            uint8_t lasterrfunc[32]; // Function name where the error occurred.

            uint8_t mountopts[64]; // Mount options as a string.
            uint32_t usrquotainodenum; // Inode number of user quota file.
            uint32_t grpquotainodenum; // Inode number of group quota file.
            uint32_t overheadblocks; // Number of overhead blocks.
            uint32_t backupbg[2]; // Block groups containing superblock backups.
            uint8_t encryptalgos[4]; // Encryption algorithms in use.
            uint8_t encryptpwdsalt[16]; // Salt used for key derivation.

            uint32_t lpfino; // Location of the lost+found inode.
            uint32_t prjquotainodenum; // Inode number of project quota file.
            uint32_t csumseed; // Checksum seed.
            uint8_t wtimehi; // High bits of write time.
            uint8_t mtimehi; // High bits of mount time.
            uint8_t mkfstimehi; // High bits of mkfs time.
            uint8_t lastcheckhi; // High bits of last check time.

            uint8_t firsterrtimehi; // High bits of first error time.
            uint8_t lasterrtimehi; // High bits of last error time.
            uint8_t firsterrcode; // Error code from first error.
            uint8_t lasterrcode; // Error code from last error.

            uint16_t encoding; // Filename encoding.
            uint16_t encodingflags; // Filename encoding flags.

            uint32_t orphanfileino; // Inode number of the orphan file.
            uint16_t defresuidhi; // High bits of default reserved UID.
            uint16_t defresgidhi; // High bits of default reserved GID.
            uint32_t reserved[93]; // Padding to make superblock 1024 bytes.
            uint32_t checksum; // Checksum of superblock at offset 0x3FC.
        } __attribute__((packed));


        struct groupdesc {
            uint32_t blockbitmaplo; // Block bitmap block.
            uint32_t inodebitmaplo; // Inode bitmap block.
            uint32_t inodetablelo; // Inode table start block.
            uint16_t freeblkcountlo; // Number of free blocks in group.
            uint16_t freeinodecountlo; // Number of free inodes in group.
            uint16_t usedircountlo;
            uint16_t flags;
            uint32_t excludebitmaplo; // Exclude bitmap for snapshots.
            uint16_t blockbitmapcsumlo; // Checksum of block bitmap.
            uint16_t inodebitmapcsumlo; // Checksum of inode bitmap.
            uint16_t itableunusedlo; // Number of unallocated inodes.
            uint16_t checksum; // Checksum of group descriptor.

            // EXT4 fields.
            uint32_t blockbitmaphi; // High 32 bits of block bitmap block.
            uint32_t inodebitmaphi; // High 32 bits of inode bitmap block.
            uint32_t inodetablehi; // High 32 bits of inode table start block
            uint16_t freeblkcounthi; // High 16 bits of number of free blocks in group.
            uint16_t freeinodecounthi; // High 16 bits of number of free
            uint16_t usedircounthi;
            uint16_t itableunusedhi; // High 16 bits of number of unallocated
            uint32_t excludebitmaphi; // High 32 bits of exclude bitmap for snapshots.
            uint16_t blockbitmapcsumhi; // High 32 bits of checksum of block
            uint16_t inodebitmapcsumhi; // High 32 bits of checksum of inode bitmap.
            uint32_t rsvd;
        } __attribute__((packed));

        #define EXT4_NDIRBLOCKS 12
        #define EXT4_INDBLOCK EXT4_NDIRBLOCKS
        #define EXT4_DINDBLOCK (EXT4_INDBLOCK + 1)
        #define EXT4_TINDBLOCK (EXT4_DINDBLOCK + 1)
        #define EXT4_NBLOCKS (EXT4_TINDBLOCK + 1)

        struct inode {
            uint16_t mode; // File mode.
            uint16_t uid; // Low 16 bits of owner UID.
            uint32_t sizelo;
            uint32_t atime; // Access time.
            uint32_t ctime; // Creation time.
            uint32_t mtime; // Modification time.
            uint32_t dtime; // Deletion time.
            uint16_t gid; // Low 16 bits of group ID.
            uint16_t linkscount; // Links count.
            uint32_t blockslo; // Blocks count.
            uint32_t flags; // File flags.
            uint32_t osd1; // OS dependent 1.
            uint32_t block[EXT4_NBLOCKS]; // Pointers to blocks.
            uint32_t generation; // File version (for NFS).
            uint32_t fileacllo; // File ACL.
            uint32_t sizethi; // High 32 bits of file size.
            uint32_t obsofaddr; // Obsoleted fragment address.

            // OSD2.
            uint16_t blkshi; // High 16 bits of blocks count.
            uint16_t aclhi; // High 16 bits of file ACL.
            uint16_t uidhi; // High 16 bits of owner UID.
            uint16_t gidhi; // High 16 bits of group ID.
            uint16_t csumlo; // Low 16 bits of inode checksum.
            uint16_t rsvd;

            uint16_t extrasize; // Size of extra inode fields.
            uint16_t csumhi; // High 16 bits of inode checksum.

            uint32_t ctimeextra; // Extra change time bits.
            uint32_t mtimeextra; // Extra modification time bits.
            uint32_t atimeextra; // Extra access time bits.
            uint32_t crtime; // Creation time.
            uint32_t crtimeextra; // Extra creation time bits.
            uint32_t versionhi; // High 32 bits for version.
            uint32_t projid; // Project ID.
        } __attribute__((packed));

        struct extenthdr {
            uint16_t magic; // Extent magic number.
            uint16_t entries; // Number of valid entries.
            uint16_t max; // Maximum number of entries that can fit.
            uint16_t depth; // Depth of extent tree.
            uint32_t generation; // Generation of the tree.
        } __attribute__((packed));

        struct extent {
            uint32_t fileblk; // First logical block extent covers.
            uint16_t len; // Number of blocks covered by extent.
            uint16_t starthi; // High 16 bits of physical block.
            uint32_t startlo; // Low 32 bits of physical block.
        } __attribute__((packed));

        struct extentidx {
            uint32_t fileblk; // First logical block extent covers.
            uint32_t leaflo; // Low 32 bits of the physical block of the next level.
            uint16_t leafhi; // High 16 bits of the physical block of the next level.
            uint16_t unused;
        } __attribute__((packed));


        enum filetype {
            FT_UNKNOWN = 0,
            FT_REG_FILE = 1,
            FT_DIR = 2,
            FT_CHRDEV = 3,
            FT_BLKDEV = 4,
            FT_FIFO = 5,
            FT_SOCK = 6,
            FT_SYMLINK = 7,
            FT_MAX = 8
        };

        // Directory entry tail for checksums (fake entry with inode=0, reclen=12).
        struct dirtail {
            uint32_t reserved; // Reserved (should be 0).
            uint16_t reclen; // Must be 12.
            uint8_t reserved_namelen; // Must be 0.
            uint8_t reserved_filetype; // Must be 0xDE (EXT4_FTDIRCSUM).
            uint32_t checksum; // CRC32c checksum.
        } __attribute__((packed));

        #define EXT4_FTDIRCSUM 0xDE

        struct direntry {
            uint32_t inode; // Inode number.
            uint16_t reclen; // Directory entry length.
            uint16_t namelen; // Name length.
            char name[255]; // File name.
        } __attribute__((packed));

        struct direntry2 {
            uint32_t inode; // Inode number.
            uint16_t reclen; // Directory entry length.
            uint8_t namelen; // Name length.
            uint8_t filetype; // File type.
            char name[255]; // File name.
        } __attribute__((packed));
    }
}

#endif