#![no_main]

use std::path::PathBuf;

use revmc::{
    interpreter::{
        opcode, Contract, DummyHost, Host, Interpreter, LoadAccountResult, SStoreResult,
        SelfDestructResult, SharedMemory,
    },
    primitives::{Address, Bytecode, Bytes, CancunSpec, Env, Log, SpecId, B256, U256},
    EvmCompiler, EvmLlvmBackend, OptimizationLevel,
};

use libfuzzer_sys::fuzz_target;

#[derive(Default)]
struct FuzzHost(DummyHost);

impl Host for FuzzHost {
    fn env(&self) -> &Env {
        self.0.env()
    }
    fn env_mut(&mut self) -> &mut Env {
        self.0.env_mut()
    }
    fn load_account(&mut self, address: Address) -> Option<LoadAccountResult> {
        self.0.load_account(address)
    }
    fn block_hash(&mut self, number: U256) -> Option<B256> {
        self.0.block_hash(number)
    }
    fn balance(&mut self, address: Address) -> Option<(U256, bool)> {
        self.0.balance(address)
    }
    fn code(&mut self, address: Address) -> Option<(Bytes, bool)> {
        self.0.code(address)
    }
    fn code_hash(&mut self, address: Address) -> Option<(B256, bool)> {
        self.0.code_hash(address)
    }
    fn sload(&mut self, address: Address, index: U256) -> Option<(U256, bool)> {
        self.0.sload(address, index)
    }
    fn sstore(&mut self, address: Address, index: U256, value: U256) -> Option<SStoreResult> {
        self.0.sstore(address, index, value)
    }
    fn tload(&mut self, address: Address, index: U256) -> U256 {
        self.0.tload(address, index)
    }
    fn tstore(&mut self, address: Address, index: U256, value: U256) {
        self.0.tstore(address, index, value);
    }
    fn log(&mut self, log: Log) {
        self.0.log(log);
    }
    // DummyHost panics for this, just ignore it here to avoid the panic
    fn selfdestruct(&mut self, _address: Address, _target: Address) -> Option<SelfDestructResult> {
        None
    }
}

fuzz_target!(|data: &[u8]| {
    let context = revmc::llvm::inkwell::context::Context::create();
    let Ok(backend) = EvmLlvmBackend::new(&context, false, OptimizationLevel::None) else {
        return;
    };
    let mut compiler = EvmCompiler::new(backend);

    if let Ok(dump_location) = std::env::var("COMPILER_DUMP") {
        compiler.set_dump_to(Some(PathBuf::from(dump_location)));
    }
    let Ok(f) = compiler.jit(Some("test"), &data, SpecId::CANCUN) else {
        return;
    };

    let mut native_host = FuzzHost::default();
    let mut native_interpreter = Interpreter::new(Contract::default(), 1_000_000, false);
    let mut shmem = SharedMemory::new();
    let native_result = unsafe {
        f.call_with_interpreter_and_memory(&mut native_interpreter, &mut shmem, &mut native_host)
    };

    let mut host = FuzzHost::default();
    let mut interpreter = Interpreter::new(
        Contract::new(
            Bytes::new(),
            Bytecode::LegacyRaw(data.to_vec().into()),
            None,
            Address::default(),
            Address::default(),
            U256::ZERO,
        ),
        1_000_000,
        false,
    );
    let table: opcode::InstructionTable<FuzzHost> =
        opcode::make_instruction_table::<FuzzHost, CancunSpec>();
    let result = interpreter.run(SharedMemory::new(), &table, &mut host);

    assert_eq!(native_result, result);
});
