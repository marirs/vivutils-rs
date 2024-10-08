#![allow(unused_variables)]

extern crate core;
use crate::analyzer::FlirtFunctionAnalyzer;
use flate2::read::GzDecoder;
use lancelot_flirt::{
    sig::parse,
    {FlirtSignature, FlirtSignatureSet},
};
use log::debug;
use std::{
    fs::{self, read, read_to_string},
    io::Read,
    rc::Rc,
};
use vivisect::{
    constants::{BR_PROC, MM_RWX, REF_CODE},
    emulator::{Emulator, GenericEmulator},
    memory::Memory,
    workspace::VivWorkspace,
};

pub mod analyzer;
pub mod emulator_drivers;
pub mod function;

pub const SHELLCODE_BASE: i32 = 0x690000;

pub fn get_shell_code_workspace_from_file(
    sample_file: &str,
    arch: &str,
    analyze: bool,
) -> VivWorkspace {
    let sample_bytes = fs::read(sample_file).unwrap();
    let mut workspace = get_shell_code_workspace(sample_bytes, Some(arch), analyze);
    workspace.set_meta("StorageName", Some(format!("{}.viv", sample_file)));
    workspace.clone()
}

/// Load shellcode into memory object and generate vivisect_rs workspace.
/// Thanks to Tom for most of the code.
/// Arguments:
/// buf: shellcode buffer bytes
/// arch: architecture string
/// base: base address where shellcode will be loaded
/// entry_point: entry point of shellcode, relative to base
/// analyze: analyze workspace or otherwise leave it to caller
/// should_save: save workspace to disk
/// save_path: path to save workspace to
/// Returns: vivisect_rs workspace
pub fn get_shell_code_workspace(
    buffer: Vec<u8>,
    arch: Option<&str>,
    _analyze: bool,
) -> VivWorkspace {
    debug!("Received {:?} bytes", buffer.len());
    let base = SHELLCODE_BASE;
    let mut workspace = VivWorkspace::new("", false);
    workspace.set_meta("Architecture", Some(arch.unwrap().to_string()));
    workspace.set_meta("Platform", Some("pe".to_string()));
    workspace.add_memory_map(base, MM_RWX, "Shellcode", buffer.clone(), None);
    workspace.add_entry_point(base); // removed: base + 0
    workspace.set_meta("Format", Some("blob".to_string()));

    workspace
}

pub fn register_flirt_signature_analyzers(
    workspace: &mut VivWorkspace,
    signature_paths: Vec<String>,
) {
    debug!("Registering Signature analyzers {}", signature_paths.len());
    for sig_path in signature_paths {
        let sigs = load_flirt_signature(sig_path.as_str());
        debug!("flirt: sig count: {}", sigs.len());
        let matcher = FlirtSignatureSet::with_signatures(sigs);
        workspace.add_analyzer(Rc::new(FlirtFunctionAnalyzer::new(matcher, sig_path)));
    }
}

pub fn load_flirt_signature(path: &str) -> Vec<FlirtSignature> {
    let mut signatures = Vec::new();
    if path.ends_with(".sig") {
        let contents = read(path).expect("Error reading .sig file.");
        signatures = parse(contents.as_slice()).unwrap();
    } else if path.ends_with(".pat") {
        let contents = read_to_string(path).expect("Error reading .pat file.");
        signatures = lancelot_flirt::pat::parse(contents.as_str()).unwrap();
    } else if path.ends_with(".pat.gz") {
        // Unzip
        let gzip_contents = read(path).expect("Error reading .pat.gz file.");
        let mut decoder = GzDecoder::new(gzip_contents.as_slice());
        let mut contents = String::new();
        decoder.read_to_string(&mut contents).unwrap();
        signatures = lancelot_flirt::pat::parse(contents.as_str()).unwrap();
    }
    signatures.clone()
}

/// get all xrefs, including fallthrough instructions, from this address.
/// vivisect_rs doesn't consider fallthroughs as xrefs.
/// see: https://github.com/fireeye/flare-ida/blob/7207a46c18a81ad801720ce0595a151b777ef5d8/python/flare/jayutils.py#L311
pub fn get_all_xrefs_from(mut workspace: VivWorkspace, va: i32) -> Vec<(i32, i32, i32, i32)> {
    let mut ret = Vec::new();
    let op = workspace.parse_op_code(va).unwrap();
    for (to_va, b_flags) in op.get_branches() {
        if (b_flags & BR_PROC) == 1 {
            continue;
        }
        ret.push((va, to_va, REF_CODE, b_flags));
    }
    ret
}

pub fn get_imagebase(workspace: VivWorkspace) -> i32 {
    let entry_point = *workspace.get_entry_points().first().unwrap();
    let base_name = workspace.get_file_by_va(entry_point);
    if let Some(basename) = base_name {
        return workspace.get_file_meta(basename.as_str(), "imagebase");
    }
    0
}

/// vivisect_rs comes with default emulation hooks (imphooks) that emulate
///
/// - API calls, e.g. GetProcAddress
/// - abstractions of library code functionality, e.g. _alloca_probe
///
/// in our testing there are inconsistencies in the hook implementation,
/// e.g. around function returns this function removes all imphooks except ones explicitly allowed
pub fn remove_default_vivi_hooks(mut emu: GenericEmulator, allow_list: Option<Vec<String>>) {
    for hook_name in emu.get_hooks() {
        if allow_list.is_some() && allow_list.as_ref().cloned().unwrap().contains(&hook_name) {
            continue;
        }
        let mut index = 0;
        let _t = emu.get_hooks().iter().find(move |x| {
            if **x == hook_name {
                true
            } else {
                index += 1;
                false
            }
        });
        emu.get_hooks().remove(index);
    }
}

pub fn is_thunk_function(_workspace: VivWorkspace, _va: i32) -> bool {
    false
}

pub fn is_library_function(_workspace: VivWorkspace, _va: i32) -> bool {
    false
}

pub fn get_function_name(_workspace: VivWorkspace, _va: i32) -> String {
    String::new()
}
