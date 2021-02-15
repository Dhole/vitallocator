// Copyright (c) 2018 Martin Larralde (martin.larralde@ens-paris-saclay.fr)
//
// Licensed under MIT license (the COPYING file). This file may not be
// copied, modified, or distributed except according to those terms.

//! A Rust allocator interface to the PS Vita kernel allocator.

#![no_std]
#![feature(allocator_api)]
#![feature(const_fn)]
#![feature(alloc_layout_extra)]

extern crate psp2_sys;

mod utils;

use core::alloc::AllocError;
use core::alloc::Allocator;
use core::alloc::GlobalAlloc;
use core::alloc::Layout;
// use core::cell::UnsafeCell;
use core::cmp::max;
use core::mem::size_of;
use core::ptr::NonNull;

use spin::Mutex;

use psp2_sys::kernel::sysmem::sceKernelAllocMemBlock;
use psp2_sys::kernel::sysmem::sceKernelFindMemBlockByAddr;
use psp2_sys::kernel::sysmem::sceKernelFreeMemBlock;
use psp2_sys::kernel::sysmem::sceKernelGetMemBlockBase;
use psp2_sys::kernel::sysmem::sceKernelGetMemBlockInfoByAddr;
use psp2_sys::kernel::sysmem::SceKernelAllocMemBlockOpt;
use psp2_sys::kernel::sysmem::SceKernelMemBlockInfo;
use psp2_sys::kernel::sysmem::SceKernelMemBlockType::SCE_KERNEL_MEMBLOCK_TYPE_USER_CDRAM_RW;
use psp2_sys::kernel::sysmem::SceKernelMemBlockType::SCE_KERNEL_MEMBLOCK_TYPE_USER_RW;
use psp2_sys::kernel::sysmem::SceKernelMemoryAccessType::SCE_KERNEL_MEMORY_ACCESS_R;
// use psp2_sys::kernel::sysmem::SceKernelMemoryAccessType::SCE_KERNEL_MEMORY_ACCESS_W;
// use psp2_sys::kernel::sysmem::SceKernelMemoryAccessType::SCE_KERNEL_MEMORY_ACCESS_X;
// use psp2_sys::kernel::threadmgr::sceKernelCreateMutex;
// use psp2_sys::kernel::threadmgr::sceKernelLockMutex;
// use psp2_sys::kernel::threadmgr::sceKernelUnlockMutex;
use psp2_sys::types::SceUID;
use psp2_sys::void;

/// A Rust interface to the PS Vita kernel allocator.
///
/// Uses the function [`sceKernelAllocMemBlock`] to allocate blocks of memory.
/// This allocator will only create blocks of `4kB`-aligned memory. It won't perform
/// the alignement itself, so you have to make sure the `size` requested [`Layout`]
/// fits this constraint !
///
/// It is not thread safe, so you'll have to rely on an external synchronisation
/// primitive, for instance by wrapping the allocator in a [`Mutex`]. As such, this
/// allocator cannot be used directly as a global allocator.
///
/// [`sceKernelAllocMemBlock`]: https://docs.vitasdk.org/group__SceSysmemUser.html
/// [`Allocator`]: https://doc.rust-lang.org/nightly/core/alloc/trait.Allocator.html
/// [`Layout`]: https://doc.rust-lang.org/nightly/core/alloc/struct.Layout.html
/// [`Mutex`]: struct.Mutex.html
pub struct VitallocatorImpl {
    block_count: usize,
}

impl VitallocatorImpl {
    pub const fn new() -> Self {
        VitallocatorImpl { block_count: 0 }
    }
}

impl VitallocatorImpl {
    fn allocate(&mut self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        // Prepare the options to pass to SceKernelAllocMemBlock
        let mut options = SceKernelAllocMemBlockOpt {
            size: size_of::<SceKernelAllocMemBlockOpt>() as u32,
            attr: SCE_KERNEL_MEMORY_ACCESS_R as u32,
            alignment: layout.align() as u32,
            uidBaseBlock: 0,
            strBaseBlockName: ::core::ptr::null(),
            flags: 0,
            reserved: [0; 10],
        };

        // Prepare the pointer
        let mut basep: *mut void = ::core::ptr::null_mut::<u8>() as *mut _;

        // Define a new name for the block (writing the block count as hex)
        let mut name: [u8; 18] = *b"__rust_0x00000000\0";
        utils::write_hex(self.block_count, &mut name[9..16]);

        // Allocate the memory block
        // let size = max(layout.size(), 4096);
        let size = if layout.size() % 4096 != 0 {
            layout.size() + (4096 - (layout.size() % 4096))
        } else {
            layout.size()
        };
        let uid: SceUID = unsafe {
            sceKernelAllocMemBlock(
                (&name).as_ptr(),
                SCE_KERNEL_MEMBLOCK_TYPE_USER_RW,
                size as i32,
                &mut options as *mut _,
            )
        };
        if uid < 0 {
            return Err(AllocError);
        }

        // Increase the block count: to the kernel, we allocated a new block.
        // `wrapping_add` avoids a panic when the total number of allocated blocks
        // exceeds `usize::max_value()`. An undefined behaviour is still expected
        // from the kernel since some block could possibly be named the same.
        self.block_count = self.block_count.wrapping_add(1);

        // Get the adress of the allocated location
        unsafe {
            if sceKernelGetMemBlockBase(uid, &mut basep as *mut *mut void) < 0 {
                sceKernelFreeMemBlock(uid); // avoid memory leak if the block cannot be used
                return Err(AllocError);
            }
        }

        // Return the obtained non-null, opaque pointer
        unsafe {
            NonNull::new(core::slice::from_raw_parts_mut(basep as *mut u8, size)).ok_or(AllocError)
        }
    }

    unsafe fn deallocate(&mut self, ptr: NonNull<u8>, layout: Layout) {
        // Get the size of the pointer memory block
        let mut info = ::core::mem::MaybeUninit::<SceKernelMemBlockInfo>::uninit();
        sceKernelGetMemBlockInfoByAddr(ptr.as_ptr() as *mut void, (info.as_mut_ptr()));
        let info = info.assume_init();

        // Find the SceUID
        let uid = sceKernelFindMemBlockByAddr(ptr.as_ptr() as *mut void, info.size);

        // Free the memory block
        sceKernelFreeMemBlock(uid);
    }
}

pub struct Vitallocator(Mutex<VitallocatorImpl>);

impl Vitallocator {
    /// Create a new kernel allocator.
    pub const fn new() -> Self {
        Self(Mutex::new(VitallocatorImpl::new()))
    }
    /// Create a kernel-compatible layout that can fit the requested layout
    unsafe fn padded(&self, layout: Layout, align: usize) -> Layout {
        let padding = layout.padding_needed_for(align);
        Layout::from_size_align_unchecked(layout.size() + padding, align)
    }
}

impl Default for Vitallocator {
    fn default() -> Self {
        Vitallocator::new()
    }
}

unsafe impl Allocator for Vitallocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        self.0.lock().allocate(layout)
    }
    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        self.0.lock().deallocate(ptr, layout)
    }
}

unsafe impl GlobalAlloc for Vitallocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.0
            .lock()
            .allocate(self.padded(layout, 4096))
            .map(|ptr| ptr.as_ptr() as *mut u8)
            .unwrap_or(::core::ptr::null_mut::<u8>())
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.0
            .lock()
            .deallocate(NonNull::new_unchecked(ptr), layout)
    }
}
