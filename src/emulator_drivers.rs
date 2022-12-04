use log::warn;
use std::rc::Rc;
use vivisect::constants::BR_TABLE;
use vivisect::emulator::{Emulator, GenericEmulator, OpCode};
use vivisect::workspace::VivWorkspace;

pub struct Monitor {}

impl Monitor {
    pub fn api_call(&self) -> bool {
        false
    }

    pub fn log_anomaly(&self, e: &str) {
        warn!("Monitor: anomaly: {}", e)
    }
}

pub struct UntilAvMonitor {
    va: i32,
}

impl UntilAvMonitor {
    pub fn new(va: i32) -> Self {
        UntilAvMonitor { va }
    }

    pub fn pre_hook<T>(&self, emu: T, op: i32, pc: i32)
    where
        T: Emulator,
    {
        if pc == self.va {
            panic!("Breakpoint hit: reason: {}", self.va);
        }
    }
}

pub trait EmuHelperMixin {
    /// Naively read ascii string.
    fn read_string(&self, va: i32, max_length: i32);

    fn get_stack_value(&self, va: i32, max_length: i32);

    fn read_stack_memory(&self, va: i32, max_length: i32);

    fn read_stack_string(&self, va: i32, max_length: i32);
}

/// this is a superclass for strategies for controlling viv emulator instances.
/// you can also treat it as an emulator instance, e.g.:
/// emu = vw.get_emulator()
/// drv = EmulatorDriver(emu)
/// drv.get_program_counter()
/// note it also inherits from EmuHelperMixin, so there are convenience routines:
/// emu = vw.getEmulator()
/// drv = EmulatorDriver(emu)
/// drv.readString(0x401000)
pub struct EmulatorDriver<T> {
    emu: T,
    monitors: Vec<Monitor>,
    hooks: Vec<i32>,
}

impl<T> EmulatorDriver<T>
where
    T: Emulator,
{
    pub fn new(emu: T) -> Self {
        EmulatorDriver {
            emu,
            monitors: Vec::new(),
            hooks: Vec::new(),
        }
    }
}

/// an emulator that attempts to explore all code paths from a given entry.
/// that is, it explores all branches encountered (though it doesn't follow calls).
/// it should emulate each instruction once (unless REP prefix, and limited to repmax iterations).
/// use a monitor to receive callbacks describing the found instructions and blocks.
pub struct FullCoverageEmulatorDriver<T> {
    emu: GenericEmulator,
    workspace: VivWorkspace,
    monitors: Vec<T>,
    hooks: Vec<i32>,
}

impl<T> FullCoverageEmulatorDriver<T> {
    pub fn new(workspace: VivWorkspace, emu: GenericEmulator, size: i32) -> Self {
        FullCoverageEmulatorDriver {
            emu,
            workspace,
            monitors: vec![],
            hooks: vec![],
        }
    }

    pub fn is_table(&self, op: OpCode, xrefs: Option<i32>) -> bool {
        if self.workspace.get_location(op.va).is_none() {
            return false;
        }
        if xrefs.is_none() {
            return false;
        }
        for (_, b_flags) in op.get_branches() {
            if b_flags & BR_TABLE == 1 {
                return true;
            }
        }
        false
    }

    /// monitors are collections of callbacks that are invoked at various places:
    /// - pre instruction emulation
    /// - post instruction emulation
    /// - during API call
    /// see the `Monitor` superclass.
    /// install monitors using this routine `add_monitor`.
    /// there can be multiple monitors added.
    pub fn add_monitor(&mut self, monitor: T) {
        self.monitors.push(monitor);
    }

    pub fn remove_monitor(&mut self, monitor: Monitor) {
        // self.monitors.contains(&monitor);
    }

    /// hooks are functions that can override APIs encountered during emulation.
    /// see the `Hook` superclass.
    /// there can be multiple hooks added, even for the same API.
    /// hooks are invoked in the order that they were added.
    pub fn add_hook(&mut self, hook: i32) {
        self.hooks.push(hook);
    }

    pub fn remove_hook(&self) {}

    pub fn is_call(&self, op: i32) {}

    pub fn run(&self, va: i32) {}
}
