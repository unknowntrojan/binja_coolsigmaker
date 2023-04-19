//!
//!	binja_coolsigmaker
//!
//! a cooler sigmaker for binja
//!
//! written by unknowntrojan
//!

#![feature(is_some_and, let_chains, core_intrinsics, iter_array_chunks)]
use std::ffi::CString;
use std::ops::Range;
use std::time::SystemTime;

use binaryninja::architecture::Architecture;

use binaryninja::binaryninjacore_sys::{
    BNBinaryView, BNCreateSettings, BNFreeRelocationRanges, BNFreeSettings, BNGetRelocationRanges,
    BNSettings, BNSettingsGetBool, BNSettingsGetUInt64, BNSettingsRegisterGroup,
    BNSettingsRegisterSetting,
};
use binaryninja::binaryview::{BinaryView, BinaryViewBase, BinaryViewExt};
use binaryninja::command::{self, AddressCommand, Command};
use clipboard::ClipboardProvider;
use findpattern::{OwnedPattern, Pattern};
use iced_x86::Code::{DeclareByte, DeclareDword, DeclareQword, DeclareWord};
use iced_x86::{ConstantOffsets, FlowControl, Formatter, Instruction, NasmFormatter, OpKind};

struct RustSigMakerCommand;
struct IDASigMakerCommand;
struct CStrSigMakerCommand;
struct SigFinderCommand;

struct RustPattern<'a>(Pattern<'a>);
struct IDAPattern<'a>(Pattern<'a>);
struct CStrPattern<'a>(Pattern<'a>);

const MAX_INSTRUCTION_LENGTH: usize = 15;

impl<'a> core::fmt::Display for RustPattern<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, x) in self.0.iter().enumerate() {
            match x {
                Some(x) => write!(f, "{:#04X}", x)?,
                None => write!(f, "_")?,
            }

            if i + 1 != self.0.len() {
                write!(f, ", ")?;
            }
        }

        Ok(())
    }
}

impl<'a> core::fmt::Display for IDAPattern<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, x) in self.0.iter().enumerate() {
            match x {
                Some(x) => write!(f, "{:02X}", x)?,
                None => write!(f, "??")?,
            }

            if i + 1 != self.0.len() {
                write!(f, " ")?;
            }
        }

        Ok(())
    }
}

impl<'a> core::fmt::Display for CStrPattern<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\"")?;

        for x in self.0.iter() {
            match x {
                Some(x) => write!(f, "\\x{:02X}", x)?,
                None => write!(f, "?")?,
            }
        }

        write!(f, "\" \"")?;

        for x in self.0.iter() {
            match x {
                Some(_) => write!(f, "x")?,
                None => write!(f, "?")?,
            }
        }

        write!(f, "\"")?;

        Ok(())
    }
}

fn get_relocation_ranges(bv: &BinaryView) -> Vec<Range<u64>> {
    let mut count = 0usize;
    let ptr = unsafe {
        BNGetRelocationRanges(
            *std::mem::transmute::<_, *mut *mut BNBinaryView>(bv),
            &mut count as *mut usize,
        )
    };

    let ranges = unsafe { std::slice::from_raw_parts(ptr, count) };

    let ret = ranges
        .iter()
        .map(|range| Range {
            start: range.start,
            end: range.end,
        })
        .collect::<Vec<_>>();

    unsafe { BNFreeRelocationRanges(ptr) };

    ret
}

fn get_code(bv: &BinaryView) -> Vec<(usize, Vec<u8>)> {
    bv.segments()
        .into_iter()
        .filter(|segment| segment.contains_code())
        .map(|segment| {
            let range = segment.address_range();
            let len = range.end.checked_sub(range.start);

            let Some(len) = len else {
				return (range.start as usize, Vec::new());
			};

            if len == 0 {
                return (range.start as usize, Vec::new());
            }

            let mut data = vec![0u8; len as usize];

            bv.read(&mut data, range.start);

            (range.start as usize, data)
        })
        .collect()
}

fn find_patterns(code_segments: &[(usize, Vec<u8>)], pattern: Pattern) -> Vec<usize> {
    if pattern.len() == 0 {
        return Vec::new();
    }

    code_segments
        .into_iter()
        .map(|segment| {
            findpattern::find_patterns(&segment.1, &pattern)
                .into_iter()
                .map(|x| x + segment.0 as usize)
                .collect::<Vec<usize>>()
        })
        .flatten()
        .collect()
}

fn get_instruction_pattern(
    bv: &BinaryView,
    start_addr: usize,
    instr: &Instruction,
    offsets: &ConstantOffsets,
    buf: &[u8],
    relocations: &[Range<u64>],
    include_operands: bool,
) -> Option<OwnedPattern> {
    let mut pattern = buf.into_iter().map(|x| Some(*x)).collect::<OwnedPattern>();

    #[allow(unused_parens)]
    if instr.is_invalid()
        || matches!(
            instr.code(),
            (DeclareByte | DeclareWord | DeclareDword | DeclareQword)
        )
    {
        log::warn!("invalid instruction encountered!");
        return None;
    }

    #[allow(unused_parens)]
    let is_branch = matches!(
        instr.flow_control(),
        (FlowControl::Call
            | FlowControl::ConditionalBranch
            | FlowControl::IndirectBranch
            | FlowControl::IndirectCall
            | FlowControl::UnconditionalBranch)
    );

    if offsets.has_displacement() {
        for x in offsets.displacement_offset()
            ..offsets.displacement_offset() + offsets.displacement_size()
        {
            pattern[x] = None;
        }
    }

    if !include_operands && offsets.has_immediate() {
        let branch_target = instr
            .op_kinds()
            .filter_map(|kind| match kind {
                OpKind::FarBranch16 => Some(instr.far_branch16() as u64 + bv.start() - 0x10000000),
                OpKind::FarBranch32 => Some(instr.far_branch32() as u64 + bv.start() - 0x10000000),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                    Some(instr.near_branch_target())
                }
                _ => None,
            })
            .nth(0);

        if is_branch && branch_target.is_some_and(|branch_target| bv.offset_valid(branch_target)) {
            for x in
                offsets.immediate_offset()..offsets.immediate_offset() + offsets.immediate_size()
            {
                pattern[x] = None;
            }
        }
    }

    if !include_operands && offsets.has_immediate2() {
        let branch_target = instr
            .op_kinds()
            .filter_map(|kind| match kind {
                OpKind::FarBranch16 => Some(instr.far_branch16() as u64 + bv.start() - 0x10000000),
                OpKind::FarBranch32 => Some(instr.far_branch32() as u64 + bv.start() - 0x10000000),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                    Some(instr.near_branch_target())
                }
                _ => None,
            })
            .nth(0);

        if is_branch && branch_target.is_some_and(|branch_target| bv.offset_valid(branch_target)) {
            for x in
                offsets.immediate_offset2()..offsets.immediate_offset2() + offsets.immediate_size2()
            {
                pattern[x] = None;
            }
        }
    }

    for relocation in relocations {
        if (start_addr..(start_addr + instr.len())).contains(&(relocation.start as usize)) {
            let start_offset = relocation.start as usize - start_addr;
            let end_offset = relocation.end as usize - start_addr;
            for x in start_offset..end_offset {
                pattern[x] = None;
            }
        }
    }

    Some(pattern)
}

fn is_pattern_unique(code_segments: &[(usize, Vec<u8>)], pattern: Pattern) -> bool {
    find_patterns(code_segments, pattern).len() == 1
}

fn create_pattern_internal(
    bv: &BinaryView,
    addr: usize,
    data: &[(usize, Vec<u8>)],
    include_operands: bool,
) -> Option<OwnedPattern> {
    log::info!("creating pattern for address {:#04X}", addr);
    let time = SystemTime::now();

    let mut formatter = NasmFormatter::new();
    formatter.options_mut().set_rip_relative_addresses(true);

    let relocations = get_relocation_ranges(bv);

    let mut current_offset = 0usize;
    let mut current_buffer = vec![0u8; MAX_INSTRUCTION_LENGTH];
    let mut current_pattern = OwnedPattern::default();
    let mut pattern_unique = false;
    let max_size = get_maximum_signature_size(bv) as usize;

    while !pattern_unique {
        if current_offset >= max_size {
            log::warn!("pattern isn't unique even at maximum size. aborting.");
            return None;
        }

        let Some(start_segment) = bv.segment_at(addr as u64) else {
			log::warn!("unable to query instruction segment");
			return None;
		};

        let Some(end_segment) = bv.segment_at((addr + current_offset) as u64) else {
			log::warn!("unable to query instruction segment");
			return None;
		};

        if !start_segment.contains_code()
            || !start_segment.readable()
            || !start_segment.executable()
            || !start_segment
                .address_range()
                .contains(&((addr + current_offset) as u64))
            || !start_segment
                .address_range()
                .contains(&((addr + current_offset + MAX_INSTRUCTION_LENGTH) as u64))
            || start_segment.address_range().start != end_segment.address_range().start
        {
            log::warn!("pattern is not unique yet, but continuing would access invalid memory.");
            return None;
        }

        current_buffer.copy_from_slice(
            &data
                .iter()
                .find(|segment| segment.0 == start_segment.address_range().start as usize)?
                .1[addr + current_offset - start_segment.address_range().start as usize
                ..addr + current_offset + MAX_INSTRUCTION_LENGTH
                    - start_segment.address_range().start as usize],
        );

        let mut decoder = iced_x86::Decoder::new(
            if let Some(arch) = bv.default_arch() {
                (arch.address_size() * 8) as u32
            } else {
                64
            },
            &current_buffer,
            0,
        );
        decoder.set_ip((addr + current_offset) as u64);

        let instr = decoder.decode();
        let offsets = decoder.get_constant_offsets(&instr);
        let instr_bytes = &current_buffer[0..instr.len()];

        let mut instr_string = String::new();
        formatter.format(&instr, &mut instr_string);

        let Some(instr_pattern) = get_instruction_pattern(bv, addr + current_offset, &instr, &offsets, instr_bytes, &relocations, include_operands) else {
			log::warn!("unable to get instruction pattern. instruction misaligned?");
			return None;
		};

        #[cfg(debug_assertions)]
        log::info!("{}: {}", instr_string, RustPattern(&instr_pattern));

        current_pattern.extend(&instr_pattern);

        current_offset += instr.len();
        pattern_unique = is_pattern_unique(&data, &current_pattern);
    }

    while let Some(x) = current_pattern.last() && x.is_none() {
		current_pattern.pop();
	}

    log::info!(
        "found pattern in {}ms",
        SystemTime::now().duration_since(time).unwrap().as_millis()
    );

    Some(current_pattern)
}

fn create_pattern(bv: &BinaryView, addr: usize) -> Option<OwnedPattern> {
    let include_operands = get_include_operands(bv);
    let data = get_code(bv);
    let pattern = create_pattern_internal(bv, addr, &data, include_operands);

    if !include_operands && pattern.is_none() {
        log::warn!("unable to find a unique pattern that didn't include operands. trying again with operands!");
        create_pattern_internal(bv, addr, &data, true)
    } else {
        pattern
    }
}

fn is_valid(bv: &BinaryView, range: Range<u64>) -> bool {
    // range is nonzero
    if bv.segment_at(range.start).is_some_and(|x| {
        x.contains_code()
            && x.address_range().contains(&range.start)
            && x.address_range().contains(&range.end)
    }) && bv.segment_at(range.end).is_some_and(|x| {
        x.contains_code()
            && x.address_range().contains(&range.start)
            && x.address_range().contains(&range.end)
    }) {
        true
    } else {
        false
    }
}

fn emit_result(contents: String) {
    log::info!("{}", &contents);
    if let Err(e) = set_clipboard_contents(contents) {
        log::error!("unable to copy to clipboard: {}", e);
    }
}

fn set_clipboard_contents(contents: String) -> Result<(), Box<dyn std::error::Error>> {
    let mut ctx: clipboard::ClipboardContext = clipboard::ClipboardProvider::new()?;

    ctx.set_contents(contents)?;

    Ok(())
}

fn get_clipboard_contents() -> Result<String, Box<dyn std::error::Error>> {
    let mut ctx: clipboard::ClipboardContext = clipboard::ClipboardProvider::new()?;

    ctx.get_contents()
}

fn get_maximum_signature_size(bv: &BinaryView) -> u64 {
    let schema_id = CString::new("default").unwrap();
    let key = CString::new("coolsigmaker.maximum_size").unwrap();
    let settings = unsafe { BNCreateSettings(schema_id.as_ptr()) };

    let ret = unsafe {
        BNSettingsGetUInt64(
            settings,
            key.as_ptr(),
            *std::mem::transmute::<_, *mut *mut BNBinaryView>(bv),
            std::ptr::null_mut(),
        )
    };

    unsafe { BNFreeSettings(settings) };

    ret
}

fn get_include_operands(bv: &BinaryView) -> bool {
    let schema_id = CString::new("default").unwrap();
    let key = CString::new("coolsigmaker.include_operands").unwrap();
    let settings = unsafe { BNCreateSettings(schema_id.as_ptr()) };

    let ret = unsafe {
        BNSettingsGetBool(
            settings,
            key.as_ptr(),
            *std::mem::transmute::<_, *mut *mut BNBinaryView>(bv),
            std::ptr::null_mut(),
        )
    };

    unsafe { BNFreeSettings(settings) };

    ret
}

fn register_settings() {
    fn register_setting<T>(
        settings: *mut BNSettings,
        name: &str,
        title: &str,
        description: &str,
        typ: &str,
        default: T,
    ) where
        T: core::fmt::Display,
    {
        let name = CString::new(name).unwrap();

        let default = if typ == "string" {
            format!("\"{}\"", default)
        } else {
            format!("{}", default)
        };

        let properties = format!(
            r#"
		{{
			"title": "{}",
			"type": "{}",
			"default": {},
			"description": "{}"
		}}
		"#,
            title, typ, default, description
        );

        let properties = CString::new(properties).unwrap();

        unsafe { BNSettingsRegisterSetting(settings, name.as_ptr(), properties.as_ptr()) };
    }

    let schema_id = CString::new("default").unwrap();
    let group = CString::new("coolsigmaker").unwrap();
    let group_fancy = CString::new("CoolSigMaker").unwrap();
    let settings = unsafe { BNCreateSettings(schema_id.as_ptr()) };

    unsafe { BNSettingsRegisterGroup(settings, group.as_ptr(), group_fancy.as_ptr()) };

    register_setting::<bool>(settings, "coolsigmaker.include_operands", "Include Operands", "Include immediate operands that aren't memory-relative or relocated when creating signatures. This results in smaller, but potentially more fragile, signatures. If no unique signature can be generated without operands, we fall back to including them.", "boolean", true);
    register_setting::<u64>(
        settings,
        "coolsigmaker.maximum_size",
        "Maximum Signature Size",
        "The maximum size the signature will accumulate before giving up.",
        "number",
        64,
    );

    unsafe { BNFreeSettings(settings) };
}

impl AddressCommand for RustSigMakerCommand {
    fn action(&self, bv: &BinaryView, addr: u64) {
        if let Some(pattern) = create_pattern(bv, addr as _) {
            emit_result(format!("{}", RustPattern(&pattern)));
        } else {
            log::error!("unable to create pattern!");
        }
    }

    fn valid(&self, bv: &BinaryView, addr: u64) -> bool {
        is_valid(
            bv,
            Range {
                start: addr,
                end: addr + MAX_INSTRUCTION_LENGTH as u64,
            },
        )
    }
}

impl AddressCommand for IDASigMakerCommand {
    fn action(&self, bv: &BinaryView, addr: u64) {
        if let Some(pattern) = create_pattern(bv, addr as _) {
            emit_result(format!("{}", IDAPattern(&pattern)));
        } else {
            log::error!("unable to create pattern!");
        }
    }

    fn valid(&self, bv: &BinaryView, addr: u64) -> bool {
        is_valid(
            bv,
            Range {
                start: addr,
                end: addr + MAX_INSTRUCTION_LENGTH as u64,
            },
        )
    }
}

impl AddressCommand for CStrSigMakerCommand {
    fn action(&self, bv: &BinaryView, addr: u64) {
        if let Some(pattern) = create_pattern(bv, addr as _) {
            emit_result(format!("{}", CStrPattern(&pattern)));
        } else {
            log::error!("unable to create pattern!");
        }
    }

    fn valid(&self, bv: &BinaryView, addr: u64) -> bool {
        is_valid(
            bv,
            Range {
                start: addr,
                end: addr + MAX_INSTRUCTION_LENGTH as u64,
            },
        )
    }
}

impl Command for SigFinderCommand {
    fn action(&self, bv: &BinaryView) {
        // please don't look a this code. its absolutely disgusting. i hate working with strings so much.

        let Ok(mut sig) = get_clipboard_contents() else {
			log::error!("unable to get signature from clipboard!");
			return;
		};

        let data = get_code(bv);

        sig = sig.replace("\n", "");
        sig = sig.replace("\r", "");
        sig = sig.replace("\t", "");
        sig = sig.trim().to_string();

        let mut pattern = OwnedPattern::new();

        if sig.contains("\"") {
            let parts = sig.split(" ").collect::<Vec<_>>();

            if parts.len() != 2 {
                log::error!("unable to parse pattern!");
                return;
            }

            let first_part = parts[0].trim().replace("\"", "");

            let first_part = first_part
                .split("\\x")
                .into_iter()
                .filter_map(|x| if x == "" { None } else { Some(x.split("?")) })
                .flatten()
                .collect::<Vec<_>>();

            let second_part = parts[1].trim().replace("\"", "");

            for (byte, mask) in first_part.iter().zip(second_part.chars()) {
                match mask {
                    'x' => {
                        let Ok(byte) = u8::from_str_radix(byte, 16) else {
							log::error!("unable to parse pattern!");
							return;
						};
                        pattern.push(Some(byte));
                    }
                    '?' => {
                        pattern.push(None);
                    }
                    _ => {
                        log::error!("invalid char encountered!");
                    }
                }
            }
        } else {
            sig = sig.replace("_", "??");
            sig = sig.replace("0x", "");
            sig = sig.replace(", ", "");
            sig = sig.replace(" ", "");

            for byte in sig.chars().array_chunks::<2>() {
                if byte == ['?', '?'] {
                    pattern.push(None);
                } else {
                    let Ok(byte) = u8::from_str_radix(
						&format!("{}{}", byte[0], byte[1]),
						16,
					) else {
						log::error!("unable to parse pattern!");
						return;
					};

                    pattern.push(Some(byte));
                }
            }
        }

        for occurrence in find_patterns(&data, &pattern) {
            log::info!("found signature at {:#04X}", occurrence);
        }

        log::info!("scan finished.");
    }

    fn valid(&self, _bv: &BinaryView) -> bool {
        true
    }
}

#[no_mangle]
pub extern "C" fn CorePluginInit() -> bool {
    binaryninja::logger::init(log::LevelFilter::Info).unwrap();

    // external_logger::init().unwrap();
    log::info!("say hello to the little ninja in your binja");

    // #[cfg(debug_assertions)]
    std::panic::set_hook(Box::new(|info| {
        let string = format!(
            "{}\n{:#?}\n{}",
            info,
            info,
            std::backtrace::Backtrace::force_capture()
        );

        // #[cfg(debug_assertions)]
        let _ = std::fs::write("C:\\log.txt", &string);

        log::info!("{}", &string);
    }));

    register_settings();

    command::register_for_address(
        "CoolSigMaker\\Create Signature from Address: Rust (0xE9, _, _, _, _)",
        "Creates a Rust-style signature from the currently selected address",
        RustSigMakerCommand {},
    );

    command::register_for_address(
        "CoolSigMaker\\Create Signature from Address: IDA (E9 ?? ?? ?? ??)",
        "Creates an IDA-style signature from the currently selected address",
        IDASigMakerCommand {},
    );

    command::register_for_address(
        "CoolSigMaker\\Create Signature from Address: CStr (\"/xE9/x00/x00/x00/x00\" \"x????\")",
        "Creates a CStr-style signature from the currently selected address",
        CStrSigMakerCommand {},
    );

    command::register(
        "CoolSigMaker\\Find Signature",
        "Finds a signature in the binary.",
        SigFinderCommand {},
    );

    true
}
