# Kenali: Enforcing Kernel Security Invariants with Data Flow Integrity

Kenali is a project aims to prevent memory-corruption-based kernel privilege escalation attacks.
It includes three major components: kernel patches, analysis, and instrumentation.
This is the prototype kernel for the Nexus 9 device,
fored from android-tegra-flounder-3.10-lollipop-release.

### Technical Details

Please check out [paper](https://www.internetsociety.org/sites/default/files/blogs-media/enforcing-kernal-security-invariants-data-flow-integrity.pdf) for more details.
Note that you'll need all three components to fully utilize the protection from Kenali.

### Build

This kernel has been tailored to be built by clang (v3.6 or higher),
with patches and scripts from the [LLVMLinux](http://llvm.linuxfoundation.org/index.php/Main_Page) projects.

To build into bootable kernel binary (tested with Google GCC toolchain):
```
make ARCH=arm64 \
    CROSS_COMPILE=${PATH_TO_GCC_BIN}/aarch64-linux-android- \
    GCC_TOOLCHAIN=${PATH_TO_GCC_BIN} \
    HOSTCC=clang CC=clang
```

To build into LLVM bitcode for static analysis:
```
make ARCH=arm64 \
    CROSS_COMPILE=${PATH_TO_GCC_BIN}/aarch64-linux-android- \
    GCC_TOOLCHAIN=${PATH_TO_GCC_BIN} \
    HOSTCC=clang-emit-bc.sh CC=clang LLVM_IR=1
```
You can download `clang-emit-bc.sh` [here](http://git.linuxfoundation.org/?p=llvmlinux.git;a=blob_plain;f=arch/all/bin/clang-emit-bc.sh;hb=HEAD).
You may need to patch this script based on the output of `file $BC_FILE`,
if it's "`LLVM bitcode`", you're good; if it's "`LLVM IR bitcode`",
then you need to replace the `grep` parameter.

### Publications
Paper
```
Enforcing Kernel Security Invariants with Data Flow Integrity
Chengyu Song, Byoungyoung Lee, Kangjie Lu, William R. Harris, Taesoo Kim, and Wenke Lee
NDSS 2016

@inproceedings{song:kenali,
  title        = {{Enforcing Kernel Security Invariants with Data Flow Integrity}},
  author       = {Chengyu Song and Byoungyoung Lee and Kangjie Lu and William R. Harris and Taesoo Kim and Wenke Lee},
  booktitle    = {Proceedings of the 2016 Annual Network and Distributed System Security Symposium (NDSS)},
  month        = feb,
  year         = 2016,
  address      = {San Diego, CA},
}
```
