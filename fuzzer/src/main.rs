//! Buffer-mode full-system fuzzer for soc2qemu ports, driven by a generated harness.toml.
//!
//! Snapshot at `target.start`, write each input to `target.input`, run until `target.end`
//! (ok) or any other stop (crash; `target.crashes` are breakpoints on known fault paths).
//!
//! Adapted from LibAFL's `fuzzers/full_system/qemu_baremetal/src/fuzzer_low_level.rs`
//! (LibAFL 0.16.1, licensed Apache-2.0 OR MIT).
use core::time::Duration;
use std::{env, fs, path::PathBuf, process};

use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::{launcher::Launcher, EventConfig},
    executors::ExitKind,
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    monitors::MultiMonitor,
    mutators::{havoc_mutations::havoc_mutations, scheduled::HavocScheduledMutator},
    observers::{CanTrack, HitcountsMapObserver, TimeObserver, VariableMapObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::StdMutationalStage,
    state::{HasCorpus, StdState},
    Error,
};
use libafl_bolts::{
    core_affinity::Cores,
    current_nanos,
    ownedref::OwnedMutSlice,
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::tuple_list,
};
use libafl_qemu::{
    command::NopCommandManager, executor::QemuExecutor, NopEmulatorDriver, NopSnapshotManager, modules::edges::StdEdgeCoverageModuleBuilder, Emulator, GuestAddr,
    GuestPhysAddr, QemuExitError, QemuExitReason, QemuRWError, QemuShutdownCause, Regs,
};
use libafl_targets::{edges_map_mut_ptr, EDGES_MAP_DEFAULT_SIZE, MAX_EDGES_FOUND};
use serde::Deserialize;

#[derive(Deserialize)]
struct Harness {
    soc: String,
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

pub fn main() {
    env_logger::init();

    let args: Vec<String> = env::args().collect();
    let harness_path = PathBuf::from(
        args.get(1)
            .cloned()
            .or_else(|| env::var("HARNESS").ok())
            .expect("usage: soc2qemu-fuzz <harness.toml> [--replay <input>]"),
    );
    let harness_dir = harness_path.parent().unwrap().to_path_buf();
    let h: Harness = toml::from_str(&fs::read_to_string(&harness_path).expect("read harness.toml"))
        .expect("parse harness.toml");

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

    if args.get(2).map(String::as_str) == Some("--replay") {
        let input = fs::read(args.get(3).expect("--replay needs an input file")).expect("read input");
        replay(&h, &input[..input.len().min(max_len)]);
        return;
    }

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

                    match emulator.qemu().run() {
                        Ok(QemuExitReason::Breakpoint(_)) => {}
                        Ok(QemuExitReason::Timeout) => return ExitKind::Timeout,
                        Ok(QemuExitReason::End(QemuShutdownCause::HostSignal(signal))) => {
                            signal.handle()
                        }
                        Err(QemuExitError::UnexpectedExit) => return ExitKind::Crash,
                        e => panic!("unexpected QEMU exit: {e:?}"),
                    }

                    // Only the end breakpoint is a clean finish; a crash breakpoint or any
                    // other stop counts as a crash.
                    let at_end = (0..qemu.num_cpus())
                        .map(|i| qemu.cpu_from_index(i).unwrap())
                        .map(|cpu| -> Result<GuestAddr, QemuRWError> {
                            cpu.read_reg(Regs::Pc).map(|pc| pc as GuestAddr)
                        })
                        .any(|pc| pc.map(|pc| pc == end).unwrap_or(false));

                    qemu.restore_fast_snapshot(snap);
                    if at_end {
                        ExitKind::Ok
                    } else {
                        ExitKind::Crash
                    }
                }
            };

        let time_observer = TimeObserver::new("time");
        let mut feedback = feedback_or!(
            MaxMapFeedback::new(&edges_observer),
            TimeFeedback::new(&time_observer)
        );
        let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

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
            tuple_list!(edges_observer, time_observer),
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

/// Run one input outside the fuzzer and report how and where it stopped.
fn replay(h: &Harness, input: &[u8]) {
    let (start, end) = (h.target.start as GuestAddr, h.target.end as GuestAddr);
    let crash_pcs: Vec<GuestAddr> = h.target.crashes.iter().map(|&a| a as GuestAddr).collect();
    // No fuzzer here, so nothing infers the input/state types; replay needs no modules or state.
    let emulator: Emulator<(), NopCommandManager, NopEmulatorDriver, (), BytesInput, (), NopSnapshotManager> =
        Emulator::empty()
        .qemu_parameters(h.qemu_args.clone())
        .modules(tuple_list!())
        .build()
        .expect("start QEMU");
    let qemu = emulator.qemu();
    unsafe {
        qemu.set_breakpoint(start);
        match qemu.run() {
            Ok(QemuExitReason::Breakpoint(_)) => {}
            e => panic!("did not reach start {start:#x}: {e:?}"),
        }
        qemu.remove_breakpoint(start);
        qemu.set_breakpoint(end);
        for &pc in &crash_pcs {
            qemu.set_breakpoint(pc);
        }
        qemu.write_phys_mem(h.target.input as GuestPhysAddr, input);
        let exit = qemu.run();
        let pc = qemu
            .cpu_from_index(0)
            .and_then(|cpu| cpu.read_reg(Regs::Pc).ok())
            .map(|pc| pc as GuestAddr);
        let verdict = match (&exit, pc) {
            (Ok(QemuExitReason::Breakpoint(_)), Some(pc)) if pc == end => "ok (end)",
            (Ok(QemuExitReason::Breakpoint(_)), Some(pc)) if crash_pcs.contains(&pc) => "crash (crash breakpoint)",
            (Ok(QemuExitReason::Timeout), _) => "timeout",
            _ => "crash (unexpected stop)",
        };
        println!("replay: {} bytes, exit {exit:?}, pc {pc:x?} -> {verdict}", input.len());
    }
}
