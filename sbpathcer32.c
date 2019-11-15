/*
 * sbpathcer32 - sandbox patcher for ios 9/10 (bootloader-base jailbreak)
 * iOS 9.0 - 10.3.3
 * Copyright (c) 2019 dora_yururi
 *
 * Requires: tfp0 and bootrom/iboot exploit
 * Supports: iOS 9.0 - 10.3.3 (armv7 only)
 *
 * BUILD
 * iOS 9.x
 * xcrun -sdk iphoneos clang sbpathcer32.c patchfinder.o -arch armv7 -framework CoreFoundation -o sbpathcer32 && ldid -Stfp0.plist sbpathcer32
 *
 * iOS 10.x (ex: put in /usr/libexec/rtbuddyd)
 * xcrun -sdk iphoneos clang sbpathcer32.c patchfinder.o -arch armv7 -framework CoreFoundation -o rtbuddyd && codesign -f -s - -i com.apple.rtbuddyd --entitlements tfp0.plist rtbuddyd
 *
 */

#include <mach/mach.h>
#include <CoreFoundation/CoreFoundation.h>
#include <mach-o/loader.h>
#include <sys/utsname.h>

#include "patchfinder.h"
#include "mac_policy.h"

#define DEFAULT_KERNEL_SLIDE    0x80000000
#define KDUMP_SIZE              0x1200000
#define CHUNK_SIZE              0x800

mach_port_t tfp0=0;
uint8_t kdump[KDUMP_SIZE] = {0};

/* -- yalu102 by qwertyoruiop -- */
kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);

void copyin(void* to, uint32_t from, size_t size) {
    mach_vm_size_t outsize = size;
    size_t szt = size;
    if (size > 0x1000) {
        size = 0x1000;
    }
    size_t off = 0;
    while (1) {
        mach_vm_read_overwrite(tfp0, off+from, size, (mach_vm_offset_t)(off+to), &outsize);
        szt -= size;
        off += size;
        if (szt == 0) {
            break;
        }
        size = szt;
        if (size > 0x1000) {
            size = 0x1000;
        }
        
    }
}

void copyout(uint32_t to, void* from, size_t size) {
    mach_vm_write(tfp0, to, (vm_offset_t)from, (mach_msg_type_number_t)size);
}

uint32_t ReadAnywhere32(uint32_t addr) {
    uint32_t val = 0;
    copyin(&val, addr, 4);
    return val;
}

uint32_t WriteAnywhere32(uint32_t addr, uint32_t val) {
    copyout(addr, &val, 4);
    return val;
}
/* -- end -- */

mach_port_t get_kernel_task() {
    task_t kernel_task;
    if (KERN_SUCCESS != task_for_pid(mach_task_self(), 0, &kernel_task)) {
        return -1;
    }
    return kernel_task;
}

vm_address_t get_kernel_base() {
    vm_region_submap_info_data_64_t info;
    vm_size_t size;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
    unsigned int depth = 0;
    vm_address_t addr = 0x81200000;
    while (1) {
        if (KERN_SUCCESS != vm_region_recurse_64(tfp0, &addr, &size, &depth, (vm_region_info_t) & info, &info_count))
            break;
        if (size > 1024 * 1024 * 1024) {
            /*
             * https://code.google.com/p/iphone-dataprotection/
             * hax, sometimes on iOS7 kernel starts at +0x200000 in the 1Gb region
             */
            pointer_t buf;
            mach_msg_type_number_t sz = 0;
            addr += 0x200000;
            vm_read(tfp0, addr + 0x1000, 512, &buf, &sz);
            if (*((uint32_t *)buf) != MH_MAGIC) {
                addr -= 0x200000;
                vm_read(tfp0, addr + 0x1000, 512, &buf, &sz);
                if (*((uint32_t*)buf) != MH_MAGIC) {
                    break;
                }
            }
            vm_address_t kbase = addr + 0x1000;
            return kbase;
        }
        addr += size;
    }
    return -1;
}

void dump_kernel(vm_address_t kernel_base, uint8_t *dest) {
    for (vm_address_t addr = kernel_base, e = 0; addr < kernel_base + KDUMP_SIZE; addr += CHUNK_SIZE, e += CHUNK_SIZE) {
        pointer_t buf = 0;
        vm_address_t sz = 0;
        vm_read(tfp0, addr, CHUNK_SIZE, &buf, &sz);
        if (buf == 0 || sz == 0)
            continue;
        bcopy((uint8_t *)buf, dest + e, CHUNK_SIZE);
    }
}

int find_ios_version() {
    struct utsname u = { 0 };
    uname(&u);
    if (strcmp(u.release, "15.0.0") == 0){
        char xnu[] = "xnu-";
        char end[] = "/";
        char *ret;
        char ver[0xf]={0};
        if ((ret = strstr(u.version, xnu)) != NULL ) {
            memcpy(ver, ret+9, 2);
        } else {
            return -1;
        }
        if (strcmp(ver, "20") == 0 || strcmp(ver, "21") == 0 || strcmp(ver, "31") == 0) {
            return 2; // 9.2-9.2.1
        } else {
            return 1; // 9.0-9.1
        }
    }
    
    if (strcmp(u.release, "15.4.0") == 0){ return 2; }
    if (strcmp(u.release, "15.5.0") == 0){ return 2; }
    if (strcmp(u.release, "15.6.0") == 0){ return 2; }
    if (strcmp(u.release, "16.0.0") == 0){ return 3; }
    if (strcmp(u.release, "16.1.0") == 0){ return 4; }
    if (strcmp(u.release, "16.3.0") == 0){ return 4; }
    if (strcmp(u.release, "16.5.0") == 0){ return 5; }
    if (strcmp(u.release, "16.6.0") == 0){ return 5; }
    if (strcmp(u.release, "16.7.0") == 0){ return 5; }
    
    return -1;
}

void patch_sandbox90(uint32_t sbops){
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops90, mpo_file_check_mmap), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_rename), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_rename), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_access), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_chroot), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_create), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_deleteextattr), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_exchangedata), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_exec), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_getattrlist), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_getextattr), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_ioctl), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_link), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_listextattr), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_open), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_readlink), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_setattrlist), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_setextattr), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_setflags), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_setmode), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_setowner), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_setutimes), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_setutimes), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_stat), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_truncate), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_unlink), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_notify_create), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops90, mpo_vnode_check_fsgetpath), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops90, mpo_mount_check_stat), 0);
}

void patch_sandbox9(uint32_t sbops){
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops9, mpo_file_check_mmap), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_rename), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_rename), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_access), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_chroot), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_create), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_deleteextattr), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_exchangedata), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_exec), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_getattrlist), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_getextattr), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_ioctl), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_link), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_listextattr), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_open), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_readlink), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_setattrlist), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_setextattr), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_setflags), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_setmode), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_setowner), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_setutimes), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_setutimes), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_stat), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_truncate), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_unlink), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_notify_create), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_fsgetpath), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops9, mpo_vnode_check_getattr), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops9, mpo_mount_check_stat), 0);
}

void patch_sandbox100(uint32_t sbops){
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops100, mpo_file_check_mmap), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_rename), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_rename), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_access), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_chroot), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_create), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_deleteextattr), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_exchangedata), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_exec), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_getattrlist), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_getextattr), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_ioctl), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_link), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_listextattr), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_open), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_readlink), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_setattrlist), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_setextattr), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_setflags), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_setmode), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_setowner), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_setutimes), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_setutimes), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_stat), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_truncate), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_unlink), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_notify_create), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops100, mpo_vnode_check_fsgetpath), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops100, mpo_mount_check_stat), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops100, mpo_proc_check_setauid), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops100, mpo_proc_check_getauid), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops100, mpo_proc_check_fork), 0);
}

void patch_sandbox101(uint32_t sbops){
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops101, mpo_file_check_mmap), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_rename), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_rename), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_access), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_chroot), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_create), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_deleteextattr), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_exchangedata), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_exec), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_getattrlist), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_getextattr), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_ioctl), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_link), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_listextattr), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_open), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_readlink), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_setattrlist), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_setextattr), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_setflags), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_setmode), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_setowner), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_setutimes), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_setutimes), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_stat), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_truncate), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_unlink), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_notify_create), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_fsgetpath), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops101, mpo_vnode_check_getattr), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops101, mpo_mount_check_stat), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops101, mpo_proc_check_setauid), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops101, mpo_proc_check_getauid), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops101, mpo_proc_check_fork), 0);
}

void patch_sandbox103(uint32_t sbops){
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_file_check_mmap), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_rename), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_rename), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_access), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_chroot), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_create), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_deleteextattr), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_exchangedata), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_exec), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_getattrlist), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_getextattr), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_ioctl), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_link), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_listextattr), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_open), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_readlink), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_setattrlist), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_setextattr), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_setflags), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_setmode), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_setowner), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_setutimes), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_setutimes), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_stat), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_truncate), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_unlink), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_notify_create), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_fsgetpath), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_vnode_check_getattr), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_mount_check_stat), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_proc_check_setauid), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_proc_check_getauid), 0);
    WriteAnywhere32(sbops+offsetof(struct mac_policy_ops103, mpo_proc_check_fork), 0);
}

int main(int argc, char *argv[]) {
    
    int mpo_ver = find_ios_version();
    if (!mpo_ver) {
        return -1;
    }
    
    // tfp0
    tfp0 = get_kernel_task();
    if (!tfp0) {
        return -1;
    }
    
    // kernbase
    vm_address_t kernbase = get_kernel_base();
    if (!kernbase) {
        return -1;
    }
    
    // kerneldump
    dump_kernel(kernbase, kdump);
    if (!(*(uint32_t*)&kdump[0] == MH_MAGIC)) {
        return -1;
    }
    
    // sandbox
    {
        uint32_t sbops = find_sbops(kernbase, kdump, KDUMP_SIZE);
        if (!sbops) {
            return -1;
        }
        
        if (mpo_ver == 1) {
            patch_sandbox90(sbops);
        }
        
        if (mpo_ver == 2) {
            patch_sandbox9(sbops);
        }
        
        if (mpo_ver == 3) {
            patch_sandbox100(sbops);
        }
        
        if (mpo_ver == 4) {
            patch_sandbox101(sbops);
        }
        
        if (mpo_ver == 5) {
            patch_sandbox103(sbops);
        }
        
    }
    
    return 0;
}
