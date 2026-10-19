//! Buffer-mode full-system fuzzer for soc2qemu ports, driven by a generated harness.toml.
//!
//! Snapshot at `target.start`, write each input to `target.input`, run until `target.end`
//! (ok) or any other stop (crash; `target.crashes` are breakpoints on known fault paths).
//! Crashes are deduplicated by signature (see `Signature`): only the first input per
//! signature is saved.
//!
//!     soc2qemu-fuzz <harness.toml>                      fuzz
//!     soc2qemu-fuzz <harness.toml> --replay <input>     run one input, report how it stopped
//!     soc2qemu-fuzz <harness.toml> --triage <dir>       group saved crashes by signature,
//!                                                      keep the smallest per group in
//!                                                      <harness dir>/crashes-unique/
//!
//! Fuzzing loop adapted from LibAFL's `fuzzers/full_system/qemu_baremetal/src/fuzzer_low_level.rs`
//! (LibAFL 0.16.1, licensed Apache-2.0 OR MIT).
use core::time::Duration;
use std::{collections::BTreeMap, env, fs, path::PathBuf, process};

use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::{launcher::Launcher, EventConfig},
    executors::ExitKind,
    feedback_and_fast, feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, NewHashFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    monitors::MultiMonitor,
    mutators::{havoc_mutations::havoc_mutations, scheduled::HavocScheduledMutator},
    observers::{CanTrack, HitcountsMapObserver, TimeObserver, ValueObserver, VariableMapObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::StdMutationalStage,
    state::{HasCorpus, StdState},
    Error,
};
use libafl_bolts::{
    core_affinity::Cores,
    current_nanos,
    ownedref::{OwnedMutSlice, OwnedRef},
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::tuple_list,
};
use libafl_qemu::{
    command::NopCommandManager, executor::QemuExecutor, modules::edges::StdEdgeCoverageModuleBuilder,
    Emulator, FastSnapshotPtr, GuestAddr, GuestPhysAddr, NopEmulatorDriver, NopSnapshotManager, Qemu,
    QemuExitError, QemuExitReason, QemuShutdownCause, Regs,
};
use libafl_targets::{edges_map_mut_ptr, EDGES_MAP_DEFAULT_SIZE, MAX_EDGES_FOUND};
use serde::Deserialize;

#[derive(Deserialize)]
struct Harness {
    soc: String,
    /// soc2qemu spec profile: "m" enables Cortex-M fault signatures.
    #[serde(default)]
    profile: String,
    qemu_args: Vec<String>,
    target: Target,
}

#[derive(Deserialize)]
struct Target {
    start: u64,
    end: u64,
    crashes: Vec<u64>,
    input: u64,
    input_max_len: usize,
    timeout_ms: u64,
}

/// Cortex-M Configurable Fault Status Register (UFSR:BFSR:MMFSR).
const CFSR: GuestAddr = 0xE000_ED28;

/// Hash of the last crash's signature, read by the dedup observer. Only the fuzzing client's
/// single thread touches it.
static mut CRASH_SIG: u64 = 0;

/// What a stop looked like, as precisely as the architecture lets us tell.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Signature {
    /// Clean finish at the end breakpoint.
    Ok,
    /// Cortex-M fault: faulting PC from the exception frame on the main stack, plus CFSR.
    MFault { pc: GuestAddr, cfsr: u32 },
    /// Cortex-M fault taken on the process stack; libafl_qemu doesn't expose PSP, so only the
    /// fault type is known.
    MFaultPsp { cfsr: u32 },
    /// Any other stop (crash breakpoint without fault info, unexpected breakpoint, timeout).
    Stop { kind: &'static str, pc: GuestAddr },
}

impl Signature {
    fn describe(&self) -> String {
        match self {
            Signature::Ok => "ok".into(),
            Signature::MFault { pc, cfsr } => format!("fault pc={pc:#x} cfsr={cfsr:#010x} ({})", cfsr_names(*cfsr)),
            Signature::MFaultPsp { cfsr } => format!("fault pc=? (process stack) cfsr={cfsr:#010x} ({})", cfsr_names(*cfsr)),
            Signature::Stop { kind, pc } => format!("{kind} pc={pc:#x}"),
        }
    }

    /// Stable within a build; FNV-1a over the description.
    fn hash(&self) -> u64 {
        self.describe()
            .bytes()
            .fold(0xcbf2_9ce4_8422_2325u64, |h, b| (h ^ b as u64).wrapping_mul(0x100_0000_01b3))
    }

    fn short(&self) -> String {
        match self {
            Signature::MFault { pc, cfsr } => format!("pc{pc:x}-cfsr{cfsr:x}"),
            Signature::MFaultPsp { cfsr } => format!("psp-cfsr{cfsr:x}"),
            Signature::Stop { kind, pc } => format!("{kind}-pc{pc:x}"),
            Signature::Ok => "ok".into(),
        }
    }
}

fn cfsr_names(cfsr: u32) -> String {
    const BITS: [(u32, &str); 17] = [
        (0, "IACCVIOL"), (1, "DACCVIOL"), (3, "MUNSTKERR"), (4, "MSTKERR"), (5, "MLSPERR"),
        (8, "IBUSERR"), (9, "PRECISERR"), (10, "IMPRECISERR"), (11, "UNSTKERR"), (12, "STKERR"),
        (13, "LSPERR"), (16, "UNDEFINSTR"), (17, "INVSTATE"), (18, "INVPC"), (19, "NOCP"),
        (24, "UNALIGNED"), (25, "DIVBYZERO"),
    ];
    let names: Vec<&str> = BITS.iter().filter(|(b, _)| cfsr & (1 << b) != 0).map(|(_, n)| *n).collect();
    if names.is_empty() { "none".into() } else { names.join("|") }
}

/// Reads the stop state after `qemu.run()` returned at a breakpoint.
fn classify(qemu: Qemu, h: &Harness, end: GuestAddr, crash_pcs: &[GuestAddr]) -> Signature {
    let Some(cpu) = qemu.cpu_from_index(0) else {
        return Signature::Stop { kind: "stop", pc: 0 };
    };
    let reg = |r: Regs| cpu.read_reg(r).map(|v| v as GuestAddr).unwrap_or(0);
    let pc = reg(Regs::Pc);
    if pc == end {
        return Signature::Ok;
    }
    if h.profile == "m" && crash_pcs.contains(&pc) {
        let mut word = [0u8; 4];
        let cfsr = cpu.read_mem(CFSR, &mut word).map(|_| u32::from_le_bytes(word)).unwrap_or(0);
        let exc_return = reg(Regs::Lr);
        // EXC_RETURN bit 2 set: the frame was pushed on PSP.
        if exc_return & 0xffff_ff00 == 0xffff_ff00 && exc_return & 0x4 != 0 {
            return Signature::MFaultPsp { cfsr };
        }
        // Basic and extended frames both keep the return address at SP + 24.
        let sp = reg(Regs::Sp);
        if cpu.read_mem(sp + 24, &mut word).is_ok() {
            return Signature::MFault { pc: u32::from_le_bytes(word) as GuestAddr, cfsr };
        }
    }
    let kind = if crash_pcs.contains(&pc) { "crash-bp" } else { "stop" };
    Signature::Stop { kind, pc }
}

pub fn main() {
    env_logger::init();

    let args: Vec<String> = env::args().collect();
    let harness_path = PathBuf::from(
        args.get(1)
            .cloned()
            .or_else(|| env::var("HARNESS").ok())
            .expect("usage: soc2qemu-fuzz <harness.toml> [--replay <input> | --triage <dir>]"),
    );
    let harness_dir = harness_path.parent().unwrap().to_path_buf();
    let h: Harness = toml::from_str(&fs::read_to_string(&harness_path).expect("read harness.toml"))
        .expect("parse harness.toml");

    match args.get(2).map(String::as_str) {
        Some("--replay") => {
            let path = PathBuf::from(args.get(3).expect("--replay needs an input file"));
            let mut r = Runner::new(&h);
            let (sig, exit) = r.run(&fs::read(&path).expect("read input"));
            println!("replay: {} -> {} [{exit}]", path.display(), sig.describe());
            return;
        }
        Some("--triage") => {
            triage(&h, &PathBuf::from(args.get(3).expect("--triage needs a directory")), &harness_dir.join("crashes-unique"));
            return;
        }
        Some(other) => panic!("unknown option {other}"),
        None => {}
    }
    fuzz(&h, &harness_dir);
}

/// One QEMU instance stopped at the snapshot point, for replay and triage.
struct Runner<'h> {
    h: &'h Harness,
    qemu: Qemu,
    snap: FastSnapshotPtr,
    _emulator: Emulator<(), NopCommandManager, NopEmulatorDriver, (), BytesInput, (), NopSnapshotManager>,
}

impl<'h> Runner<'h> {
    fn new(h: &'h Harness) -> Self {
        // No fuzzer here, so nothing infers the input/state types; no modules or state needed.
        let emulator: Emulator<(), NopCommandManager, NopEmulatorDriver, (), BytesInput, (), NopSnapshotManager> =
            Emulator::empty()
                .qemu_parameters(h.qemu_args.clone())
                .modules(tuple_list!())
                .build()
                .expect("start QEMU");
        let qemu = emulator.qemu();
        let start = h.target.start as GuestAddr;
        unsafe {
            qemu.set_breakpoint(start);
            match qemu.run() {
                Ok(QemuExitReason::Breakpoint(_)) => {}
                e => panic!("did not reach start {start:#x}: {e:?}"),
            }
            qemu.remove_breakpoint(start);
        }
        qemu.set_breakpoint(h.target.end as GuestAddr);
        for &pc in &h.target.crashes {
            qemu.set_breakpoint(pc as GuestAddr);
        }
        let snap = qemu.create_fast_snapshot(true);
        Self { h, qemu, snap, _emulator: emulator }
    }

    /// Run one input from the snapshot; returns its signature and the raw exit for display.
    fn run(&mut self, input: &[u8]) -> (Signature, String) {
        let t = &self.h.target;
        let crash_pcs: Vec<GuestAddr> = t.crashes.iter().map(|&a| a as GuestAddr).collect();
        unsafe {
            self.qemu.write_phys_mem(t.input as GuestPhysAddr, &input[..input.len().min(t.input_max_len)]);
            let exit = self.qemu.run();
            let sig = match &exit {
                Ok(QemuExitReason::Breakpoint(_)) => classify(self.qemu, self.h, t.end as GuestAddr, &crash_pcs),
                _ => Signature::Stop { kind: "exit", pc: 0 },
            };
            self.qemu.restore_fast_snapshot(self.snap);
            (sig, format!("{exit:?}"))
        }
    }
}

fn triage(h: &Harness, dir: &PathBuf, out: &PathBuf) {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .expect("read crash dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file() && !p.file_name().unwrap().to_string_lossy().starts_with('.'))
        .collect();
    files.sort();
    let mut r = Runner::new(h);
    let mut groups: BTreeMap<Signature, Vec<(usize, PathBuf)>> = BTreeMap::new();
    for f in files {
        let data = fs::read(&f).expect("read input");
        let (sig, _) = r.run(&data);
        groups.entry(sig).or_default().push((data.len(), f));
    }
    fs::create_dir_all(out).expect("create output dir");
    let crashing = groups.keys().filter(|s| **s != Signature::Ok).count();
    println!("{crashing} unique crash signature(s):");
    for (sig, mut inputs) in groups {
        inputs.sort();
        let (len, best) = &inputs[0];
        if sig == Signature::Ok {
            println!("  {:>4} input(s) no longer crash", inputs.len());
            continue;
        }
        let name = format!("{}-{}", sig.short(), best.file_name().unwrap().to_string_lossy());
        fs::copy(best, out.join(&name)).expect("copy input");
        println!("  {:>4} input(s)  {}  smallest {len} bytes -> {}", inputs.len(), sig.describe(), out.join(&name).display());
    }
}

fn fuzz(h: &Harness, harness_dir: &PathBuf) {
    let start = h.target.start as GuestAddr;
    let end = h.target.end as GuestAddr;
    let crash_pcs: Vec<GuestAddr> = h.target.crashes.iter().map(|&a| a as GuestAddr).collect();
    let input_addr = h.target.input as GuestPhysAddr;
    let max_len = h.target.input_max_len;
    let timeout = Duration::from_millis(h.target.timeout_ms);
    println!(
        "{}: start {start:#x}, end {end:#x}, crashes {crash_pcs:x?}, input {input_addr:#x} ({max_len} bytes)",
        h.soc
    );

    let cores = Cores::from_cmdline(&env::var("CORES").unwrap_or_else(|_| "1".into())).unwrap();
    let broker_port: u16 = env::var("BROKER_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(1338);
    let corpus_dirs = [harness_dir.join("corpus")];
    let objective_dir = harness_dir.join("crashes");

    let mut run_client = |state: Option<_>, mut mgr, _client_description| {
        let mut edges_observer = unsafe {
            HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
                "edges",
                OwnedMutSlice::from_raw_parts_mut(edges_map_mut_ptr(), EDGES_MAP_DEFAULT_SIZE),
                &raw mut MAX_EDGES_FOUND,
            ))
            .track_indices()
        };
        // The harness writes CRASH_SIG before reporting a crash; NewHashFeedback keeps only
        // crashes whose signature it hasn't seen in this client's state.
        let sig_observer = ValueObserver::new("crash_sig", unsafe { OwnedRef::from_ptr(&raw const CRASH_SIG) });

        let emulator_modules = tuple_list!(StdEdgeCoverageModuleBuilder::default()
            .map_observer(edges_observer.as_mut())
            .build()?);

        let emulator = Emulator::empty()
            .qemu_parameters(h.qemu_args.clone())
            .modules(emulator_modules)
            .build()?;
        let qemu = emulator.qemu();

        // Boot to the snapshot point.
        qemu.set_breakpoint(start);
        unsafe {
            match qemu.run() {
                Ok(QemuExitReason::Breakpoint(_)) => {}
                e => panic!("did not reach start {start:#x}: {e:?}"),
            }
        }
        qemu.remove_breakpoint(start);

        qemu.set_breakpoint(end);
        for &pc in &crash_pcs {
            qemu.set_breakpoint(pc);
        }
        let snap = qemu.create_fast_snapshot(true);

        let mut harness =
            |emulator: &mut Emulator<_, _, _, _, _, _, _>, _state: &mut _, input: &BytesInput| {
                let target = input.target_bytes();
                let buf = &target[..target.len().min(max_len)];
                unsafe {
                    qemu.write_phys_mem(input_addr, buf);

                    let sig = match emulator.qemu().run() {
                        Ok(QemuExitReason::Breakpoint(_)) => classify(qemu, h, end, &crash_pcs),
                        Ok(QemuExitReason::Timeout) => {
                            let pc = qemu.cpu_from_index(0).and_then(|c| c.read_reg(Regs::Pc).ok()).map_or(0, |v| v as GuestAddr);
                            Signature::Stop { kind: "timeout", pc }
                        }
                        Ok(QemuExitReason::End(QemuShutdownCause::HostSignal(signal))) => {
                            // The fuzzer is being stopped; don't let this input count as a crash.
                            signal.handle();
                            qemu.restore_fast_snapshot(snap);
                            return ExitKind::Ok;
                        }
                        Err(QemuExitError::UnexpectedExit) => Signature::Stop { kind: "exit", pc: 0 },
                        e => panic!("unexpected QEMU exit: {e:?}"),
                    };
                    qemu.restore_fast_snapshot(snap);

                    match sig {
                        Signature::Ok => ExitKind::Ok,
                        Signature::Stop { kind: "timeout", .. } => {
                            CRASH_SIG = sig.hash();
                            ExitKind::Timeout
                        }
                        _ => {
                            CRASH_SIG = sig.hash();
                            ExitKind::Crash
                        }
                    }
                }
            };

        let time_observer = TimeObserver::new("time");
        let mut feedback = feedback_or!(
            MaxMapFeedback::new(&edges_observer),
            TimeFeedback::new(&time_observer)
        );
        let mut objective = feedback_and_fast!(
            feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new()),
            NewHashFeedback::new(&sig_observer)
        );

        let mut state = state.unwrap_or_else(|| {
            StdState::new(
                StdRand::with_seed(current_nanos()),
                InMemoryCorpus::new(),
                OnDiskCorpus::new(objective_dir.clone()).unwrap(),
                &mut feedback,
                &mut objective,
            )
            .unwrap()
        });

        let scheduler =
            IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        let mut executor = QemuExecutor::new(
            emulator,
            &mut harness,
            tuple_list!(edges_observer, time_observer, sig_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
            timeout,
        )
        .expect("Failed to create QemuExecutor");
        executor.break_on_timeout();

        if state.must_load_initial_inputs() {
            state
                .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &corpus_dirs)
                .unwrap_or_else(|err| {
                    println!("Failed to load initial corpus at {corpus_dirs:?}: {err:?}");
                    process::exit(0);
                });
            println!("Imported {} inputs from disk.", state.corpus().count());
        }

        let mutator = HavocScheduledMutator::new(havoc_mutations());
        let mut stages = tuple_list!(StdMutationalStage::new(mutator));
        // Returns Err(ShuttingDown) on Ctrl-C/SIGINT; the launcher handles it.
        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
        Ok(())
    };

    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");
    let monitor = MultiMonitor::new(|s| println!("{s}"));
    match Launcher::builder()
        .shmem_provider(shmem_provider)
        .broker_port(broker_port)
        .configuration(EventConfig::from_build_id())
        .monitor(monitor)
        .run_client(&mut run_client)
        .cores(&cores)
        .build()
        .launch()
    {
        Ok(()) => (),
        Err(Error::ShuttingDown) => println!("Fuzzing stopped by user. Good bye."),
        Err(err) => panic!("Failed to run launcher: {err:?}"),
    }
}
