#![allow(clippy::needless_doctest_main)]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(test), warn(unused_extern_crates))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

#[macro_use]
extern crate tracing;
#[macro_use]
extern crate revmc_backend;

// For features.
use alloy_primitives as _;

mod bytecode;
pub use bytecode::*;

mod compiler;
pub use compiler::EvmCompiler;

mod linker;
pub use linker::Linker;

#[cfg(test)]
mod tests;

#[allow(ambiguous_glob_reexports)]
#[doc(inline)]
pub use revmc_backend::*;
#[allow(ambiguous_glob_reexports)]
#[doc(inline)]
pub use revmc_context::*;

#[cfg(feature = "llvm")]
#[doc(no_inline)]
pub use llvm::EvmLlvmBackend;
#[cfg(feature = "llvm")]
#[doc(inline)]
pub use revmc_llvm as llvm;

#[cfg(feature = "cranelift")]
#[doc(no_inline)]
pub use cranelift::EvmCraneliftBackend;
#[cfg(feature = "cranelift")]
#[doc(inline)]
pub use revmc_cranelift as cranelift;

#[doc(no_inline)]
pub use revm_interpreter::{self as interpreter, primitives};

const I256_MIN: U256 = U256::from_limbs([
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
    0x8000000000000000,
]);

/// Creates a new LLVM backend with the default builtin functions.
#[cfg(feature = "llvm")]
#[inline]
#[deprecated = "use `EvmLlvmBackend::new` instead"]
pub fn new_llvm_backend(
    cx: &llvm::inkwell::context::Context,
    aot: bool,
    opt_level: OptimizationLevel,
) -> Result<EvmLlvmBackend<'_>> {
    EvmLlvmBackend::new(cx, aot, opt_level)
}

/// Enable for `cargo asm -p revmc --lib`.
#[cfg(any())]
pub fn generate_all_assembly() -> EvmCompiler<EvmLlvmBackend<'static>> {
    let cx = Box::leak(Box::new(llvm::inkwell::context::Context::create()));
    let mut compiler =
        EvmCompiler::new(EvmLlvmBackend::new(cx, OptimizationLevel::Aggressive).unwrap());
    let _ = compiler.jit(None, &[], primitives::SpecId::ARROW_GLACIER).unwrap();
    unsafe { compiler.clear().unwrap() };
    compiler
}
