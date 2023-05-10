//!
//!	binja_coolsigmaker
//!
//! a cooler sigmaker for binja
//!
//! written by unknowntrojan
//!

#![feature(let_chains, core_intrinsics, iter_array_chunks)]
use std::ffi::{CStr, CString};
use std::fmt::Display;
use std::ops::Range;
use std::str::FromStr;
use std::sync::atomic::AtomicUsize;
use std::time::SystemTime;

use binaryninja::architecture::Architecture;

use binaryninja::binaryninjacore_sys::{
    BNBinaryView, BNCreateSettings, BNFreeRelocationRanges, BNFreeSettings, BNFreeString,
    BNGetRelocationRanges, BNSettings, BNSettingsGetBool, BNSettingsGetString, BNSettingsGetUInt64,
    BNSettingsRegisterGroup, BNSettingsRegisterSetting,
};
use binaryninja::binaryview::{BinaryView, BinaryViewBase, BinaryViewExt};
use binaryninja::command::{self, AddressCommand, Command};
use clipboard::ClipboardProvider;
use iced_x86::Code::{DeclareByte, DeclareDword, DeclareQword, DeclareWord};
use iced_x86::{ConstantOffsets, FlowControl, Formatter, Instruction, NasmFormatter, OpKind};
use rayon::prelude::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use rayon::slice::ParallelSlice;
use strum::{
    Display, EnumIter, EnumMessage, EnumString, EnumVariantNames, IntoEnumIterator, VariantNames,
};

type OwnedPattern = Vec<Option<u8>>;
type Pattern<'a> = &'a [Option<u8>];

#[derive(EnumIter, EnumVariantNames, EnumMessage, EnumString, Display)]
enum SignatureType {
    #[strum(message = "IDA-style signature with one ? wildcard per byte. (E9 ? ? ? ? 90)")]
    IDAOne,
    #[strum(message = "IDA-style signature with two ? wildcards per byte. (E9 ?? ?? ?? ?? 90)")]
    IDATwo,
    #[strum(message = "Rust-style signature. (0xE9, _, _, _, _, 0x90)")]
    Rust,
    #[strum(message = "CStr-style signature. (\"\\xE9\\x00\\x00\\x00\\x00\\x90\", \"x????x\")")]
    CStr,
}

impl Default for SignatureType {
    fn default() -> Self {
        Self::IDATwo
    }
}

struct SigMakerCommand;
struct SigFinderCommand;

struct RustPattern<'a>(Pattern<'a>);
struct IDAOnePattern<'a>(Pattern<'a>);
struct IDATwoPattern<'a>(Pattern<'a>);
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

impl<'a> core::fmt::Display for IDAOnePattern<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, x) in self.0.iter().enumerate() {
            match x {
                Some(x) => write!(f, "{:02X}", x)?,
                None => write!(f, "?")?,
            }

            if i + 1 != self.0.len() {
                write!(f, " ")?;
            }
        }

        Ok(())
    }
}

impl<'a> core::fmt::Display for IDATwoPattern<'a> {
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

fn find_patterns<'a>(
    code_segments: &'a [(usize, Vec<u8>)],
    pattern: Pattern<'a>,
) -> impl ParallelIterator<Item = usize> + 'a {
    fn find_patterns_internal_par<'a>(
        region: &'a [u8],
        pattern: Pattern<'a>,
    ) -> impl ParallelIterator<Item = usize> + 'a {
        #[inline(always)]
        fn match_pattern(window: &[u8], pattern: Pattern) -> bool {
            window.iter().zip(pattern).all(|(v, p)| match p {
                Some(x) => *v == *x,
                None => true,
            })
        }

        region
            .par_windows(pattern.len())
            .enumerate()
            .filter(|(_, wnd)| core::intrinsics::unlikely(match_pattern(wnd, pattern)))
            .map(|(idx, _)| idx)
    }

    let pattern = pattern.clone();

    code_segments
        .par_iter()
        .map(|segment| {
            find_patterns_internal_par(&segment.1, pattern).map(|x| x + segment.0 as usize)
        })
        .flatten()
}

fn is_pattern_unique(code_segments: &[(usize, Vec<u8>)], pattern: Pattern) -> bool {
    let iter = find_patterns(code_segments, pattern);

    let count = AtomicUsize::new(0);

    iter.find_any(|_| {
        count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        count.load(std::sync::atomic::Ordering::Relaxed) > 1
    })
    .is_none()
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

fn get_signature_type(bv: &BinaryView) -> SignatureType {
    let schema_id = CString::new("default").unwrap();
    let key = CString::new("coolsigmaker.sig_type").unwrap();
    let settings = unsafe { BNCreateSettings(schema_id.as_ptr()) };

    let ret = unsafe {
        BNSettingsGetString(
            settings,
            key.as_ptr(),
            *std::mem::transmute::<_, *mut *mut BNBinaryView>(bv),
            std::ptr::null_mut(),
        )
    };

    let string = unsafe { CStr::from_ptr(ret) };

    let sig_type = SignatureType::from_str(&string.to_string_lossy()).unwrap();

    unsafe { BNFreeString(ret) };

    unsafe { BNFreeSettings(settings) };

    sig_type
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
			"title": "{title}",
			"type": "{typ}",
			"default": {default},
			"description": "{description}",
			"ignore": ["SettingsProjectScope", "SettingsResourceScope"]
		}}
		"#
        );

        let properties = CString::new(properties).unwrap();

        unsafe { BNSettingsRegisterSetting(settings, name.as_ptr(), properties.as_ptr()) };
    }

    fn register_enum_setting<T>(
        settings: *mut BNSettings,
        name: &str,
        title: &str,
        description: &str,
    ) where
        T: Display + EnumMessage + VariantNames + IntoEnumIterator + Default,
    {
        let name = CString::new(name).unwrap();

        let enum_variants = T::VARIANTS;
        let enum_descriptions = T::iter()
            .map(|x| x.get_message().unwrap_or(""))
            .collect::<Vec<_>>();

        let properties = format!(
            r#"
		{{
			"title": "{title}",
			"type": "string",
			"default": "{}",
			"description": "{description}",
			"ignore": ["SettingsProjectScope", "SettingsResourceScope"],
			"enum": {},
			"enumDescriptions": {}
		}}
		"#,
            T::default(),
            serde_json::to_string(enum_variants).unwrap(),
            serde_json::to_string(&enum_descriptions).unwrap()
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

    register_enum_setting::<SignatureType>(
        settings,
        "coolsigmaker.sig_type",
        "Signature Type",
        "The signature type to use for creating and finding signatures",
    );

    unsafe { BNFreeSettings(settings) };
}

fn prepare_pattern(pattern: &str) -> String {
    let mut pattern = pattern.to_string();
    pattern = pattern.replace("\n", "");
    pattern = pattern.replace("\r", "");
    pattern = pattern.replace("\t", "");
    pattern = pattern.trim().to_string();

    pattern
}

fn parse_idaone_pattern(pattern: &str) -> Option<OwnedPattern> {
    // E9 ? ? ? ? 90 90
    let mut pattern = prepare_pattern(pattern);

    pattern = pattern.replace("?", "??");
    parse_idatwo_pattern(&pattern)
}

fn parse_idatwo_pattern(pattern: &str) -> Option<OwnedPattern> {
    // E9 ?? ?? ?? ?? 90 90
    let mut pattern = prepare_pattern(pattern);
    pattern = pattern.replace(" ", "");

    pattern
        .chars()
        .array_chunks::<2>()
        .try_fold(OwnedPattern::new(), |mut acc, byte| {
            if byte == ['?', '?'] {
                acc.push(None);
            } else {
                let Ok(byte) = u8::from_str_radix(
				&format!("{}{}", byte[0], byte[1]),
				16,
			) else {
				log::error!("unable to parse pattern!");
				return None;
			};

                acc.push(Some(byte));
            }

            Some(acc)
        })
}

fn parse_rust_pattern(pattern: &str) -> Option<OwnedPattern> {
    // 0xE9, _, _, _, _, 0x90, 0x90
    let mut pattern = prepare_pattern(pattern);

    pattern = pattern.replace(",", "");
    pattern = pattern.replace("0x", "");
    pattern = pattern.replace("_", "??");

    parse_idatwo_pattern(&pattern)
}

fn parse_cstr_pattern(pattern: &str) -> Option<OwnedPattern> {
    // "\xE9\x00\x00\x00\x90\x90" "x????xx"
    let pattern = prepare_pattern(pattern);

    let parts = pattern.split(" ").collect::<Vec<_>>();

    if parts.len() != 2 {
        log::error!("unable to parse pattern!");
        return None;
    }

    let first_part = parts[0].trim().replace("\"", "");

    let first_part = first_part
        .split("\\x")
        .into_iter()
        .map(|x| {
            if x == "" || x.len() < 2 {
                vec![]
            } else {
                let byte = &x[..2];
                let wildcards = x.len() - 2;

                let wildcards = (0..wildcards)
                    .into_iter()
                    .map(|_| None)
                    .collect::<Vec<Option<u8>>>();

                let mut result = vec![u8::from_str_radix(&byte, 16)
                    .map_err(|x| {
                        log::error!("unable to parse pattern!");
                        x
                    })
                    .ok()];

                result.extend(wildcards);

                result
            }
        })
        .flatten()
        .collect::<Vec<_>>();

    let second_part = parts[1].trim().replace("\"", "");

    let mut pattern = OwnedPattern::new();

    for (byte, mask) in first_part.iter().zip(second_part.chars()) {
        match mask {
            'x' => {
                pattern.push(Some(byte.unwrap()));
            }
            '?' => {
                pattern.push(None);
            }
            _ => {
                log::error!("invalid char encountered!");
            }
        }
    }

    Some(pattern)
}

#[test]
fn test_patterns() {
    let test_pattern = &[Some(0xE9), None, None, None, None, Some(0x90), Some(0x90)];
    assert_eq!(
        &parse_idaone_pattern("E9 ? ? ? ? 90 90").unwrap(),
        test_pattern
    );
    assert_eq!(
        &parse_idatwo_pattern("E9 ?? ?? ?? ?? 90 90").unwrap(),
        test_pattern
    );
    assert_eq!(
        &parse_rust_pattern("0xE9, _, _, _, _, 0x90, 0x90").unwrap(),
        test_pattern
    );
    assert_eq!(
        &parse_cstr_pattern(r#""\xE9\x00??\x00\x90\x90" "x????xx""#).unwrap(),
        test_pattern
    );
}

impl AddressCommand for SigMakerCommand {
    fn action(&self, bv: &BinaryView, addr: u64) {
        if let Some(pattern) = create_pattern(bv, addr as _) {
            let pattern: Box<dyn core::fmt::Display> = match get_signature_type(bv) {
                SignatureType::IDAOne => Box::new(IDAOnePattern(&pattern)),
                SignatureType::IDATwo => Box::new(IDATwoPattern(&pattern)),
                SignatureType::Rust => Box::new(RustPattern(&pattern)),
                SignatureType::CStr => Box::new(CStrPattern(&pattern)),
            };
            emit_result(format!("{}", pattern));
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
        let Ok(sig) = get_clipboard_contents() else {
			log::error!("unable to get signature from clipboard!");
			return;
		};

        let data = get_code(bv);

        let Some(pattern) = (match get_signature_type(bv) {
            SignatureType::IDAOne => parse_idaone_pattern(&sig),
            SignatureType::IDATwo => parse_idatwo_pattern(&sig),
            SignatureType::Rust => parse_rust_pattern(&sig),
            SignatureType::CStr => parse_cstr_pattern(&sig),
        }) else {
			log::error!("failed to parse pattern.");
			return;
		};

        find_patterns(&data, &pattern)
            .for_each(|occurrence| log::info!("found signature at {:#04X}", occurrence));

        log::info!("scan finished.");
    }

    fn valid(&self, _bv: &BinaryView) -> bool {
        true
    }
}

#[no_mangle]
pub extern "C" fn CorePluginInit() -> bool {
    binaryninja::logger::init(log::LevelFilter::Info).unwrap();

    // TODO: (maybe) if signature not found, maybe go back a few instructions and attempt to create a signature with an offset.

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
        "CSM - Create Signature from Address",
        "Creates a Signature from the currently selected address",
        SigMakerCommand {},
    );

    command::register(
        "CSM - Find Signature",
        "Finds a signature in the binary.",
        SigFinderCommand {},
    );

    true
}
