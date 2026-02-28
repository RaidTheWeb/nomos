# Nomos

Nomos is a multi-architecture unix-like kernel written in C++, aiming for stability and efficiency.

The name "Nomos" comes from the name of the [Ancient Greek daemon](https://en.wikipedia.org/wiki/Nomos_(mythology)) of Law.

## Features

- [CFS](https://en.wikipedia.org/wiki/Completely_Fair_Scheduler)-inspired SMP-capable scheduler.
- [Demand Paging](https://en.wikipedia.org/wiki/Demand_paging) for files.
- NVMe driver.
- AHCI driver (SATA support).
- ext4/ext3/ext2 filesystem support (albeit, no journaling for ext4/ext3).
- Asynchronous I/O.
- POSIX interface.

## Building

>[!warning]
>This repository only contains the Nomos kernel. Without a supporting operating system distribution like [Kairos](https://github.com/RaidTheWeb/kairos), Nomos is not very useful.

Nomos depends upon [Flanterm](https://codeberg.org/mintsuki/flanterm/) and [uACPI](https://github.com/uACPI/uACPI) for compilation. These repositories will have to be `git clone`d into the root of this repository before compilation.

Additionally, the [Limine](https://github.com/limine-bootloader/limine) boot protocol headers will have to be downloaded to `src/include/limine.h`.

```sh
# Excerpt from Kairos recipes/nomos.

curl -Lo src/include/limine.h https://raw.githubusercontent.com/limine-bootloader/limine/refs/heads/v9.x/limine.h
git clone https://codeberg.org/mintsuki/flanterm
git clone https://github.com/uACPI/uACPI

ARCH=x86_64 make # Build kernel for x86_64 target.

# Optionally: `DEST_DIR="<destination>" make install` to install the kernel to a particular location.
```

