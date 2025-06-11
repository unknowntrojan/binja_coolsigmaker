//!
//!	binja_coolsigmaker
//!
//! a cooler sigmaker for binja
//!
//! Copyright (C) 2023  unknowntrojan
//! This program is free software: you can redistribute it and/or modify
//! it under the terms of the GNU Affero General Public License as published
//! by the Free Software Foundation, either version 3 of the License, or
//! (at your option) any later version.
//!
//! This program is distributed in the hope that it will be useful,
//! but WITHOUT ANY WARRANTY; without even the implied warranty of
//! MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//! GNU Affero General Public License for more details.
//!
//! You should have received a copy of the GNU Affero General Public License
//! along with this program.  If not, see <https://www.gnu.org/licenses/>.
//!

#![feature(let_chains, iter_array_chunks)]
use std::borrow::Cow;

use std::fmt::Display;
use std::ops::Range;
use std::str::FromStr;
use std::sync::atomic::AtomicUsize;
use std::time::SystemTime;

use binary_search::{binary_search, Direction};
use binaryninja::settings::Settings;
use binaryninja::{
    architecture::Architecture,
    binary_view::{BinaryView, BinaryViewBase, BinaryViewExt},
    command::{self, AddressCommand, Command},
};

use clipboard::ClipboardProvider;
use coolfindpattern::PatternSearcher;
use iced_x86::{
    Code::{DeclareByte, DeclareDword, DeclareQword, DeclareWord},
    ConstantOffsets, FlowControl, Formatter, Instruction, NasmFormatter, OpKind,
};
use rayon::prelude::ParallelBridge;
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use strum::{Display, EnumIter, EnumMessage, EnumString, IntoEnumIterator, VariantNames};

type OwnedPattern = Vec<Option<u8>>;
type Pattern<'a> = &'a [Option<u8>];

#[derive(EnumIter, VariantNames, EnumMessage, EnumString, Display)]
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

#[derive(thiserror::Error, Debug)]
enum SignatureError {
    #[error("pattern is not unique even at size of {0} bytes! we either hit the limit or would have broken a function boundary.")]
    NotUnique(u64),
    #[error("encountered an invalid instruction")]
    InvalidInstruction,
    #[error("unable to query instruction's segment")]
    InvalidSegment,
}

struct RustPattern<'a>(Cow<'a, OwnedPattern>);
struct IDAOnePattern<'a>(Cow<'a, OwnedPattern>);
struct IDATwoPattern<'a>(Cow<'a, OwnedPattern>);
struct CStrPattern<'a>(Cow<'a, OwnedPattern>);

const MAX_INSTRUCTION_LENGTH: u64 = 15;

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

impl FromSignature for OwnedPattern {}

trait FromSignature {
    fn from_signature(mut pattern: String, signature_type: SignatureType) -> Option<OwnedPattern> {
        log::info!("attempting to parse a {signature_type}-style signature! \"{pattern}\"");

        pattern = pattern.replace("\n", "");
        pattern = pattern.replace("\r", "");
        pattern = pattern.replace("\t", "");
        pattern = pattern.trim().to_string();

        pub fn parse_idaone(mut pattern: String) -> Option<OwnedPattern> {
            // E9 ? ? ? ? 90 90
            pattern = pattern.replace("?", "??");
            parse_idatwo(pattern)
        }

        fn parse_idatwo(mut pattern: String) -> Option<OwnedPattern> {
            // E9 ?? ?? ?? ?? 90 90
            pattern = pattern.replace(" ", "");

            pattern
                .chars()
                .array_chunks::<2>()
                .try_fold(OwnedPattern::new(), |mut acc, byte| {
                    if byte == ['?', '?'] {
                        acc.push(None);
                    } else {
                        let Ok(byte) = u8::from_str_radix(&format!("{}{}", byte[0], byte[1]), 16)
                        else {
                            log::error!("unable to parse pattern!");
                            return None;
                        };

                        acc.push(Some(byte));
                    }

                    Some(acc)
                })
        }

        fn parse_rust(mut pattern: String) -> Option<OwnedPattern> {
            // 0xE9, _, _, _, _, 0x90, 0x9
            pattern = pattern.replace(",", "");
            pattern = pattern.replace("0x", "");
            pattern = pattern.replace("_", "??");

            parse_idatwo(pattern)
        }

        fn parse_cstr(pattern: String) -> Option<OwnedPattern> {
            // "\xE9\x00\x00\x00\x90\x90" "x????xx"

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

        match signature_type {
            SignatureType::IDAOne => parse_idaone(pattern),
            SignatureType::IDATwo => parse_idatwo(pattern),
            SignatureType::Rust => parse_rust(pattern),
            SignatureType::CStr => parse_cstr(pattern),
        }
    }
}

fn get_code(bv: &BinaryView) -> Vec<(u64, Vec<u8>)> {
    bv.segments()
        .into_iter()
        .filter(|segment| segment.executable() || segment.contains_code())
        .map(|segment| {
            let range = segment.address_range();
            let len = range.end.checked_sub(range.start);

            let Some(len) = len else {
                return (range.start, Vec::new());
            };

            if len == 0 {
                return (range.start, Vec::new());
            }

            let mut data = vec![0u8; len as usize];

            bv.read(&mut data, range.start);

            (range.start, data)
        })
        .collect()
}

fn get_instruction_pattern(
    bv: &BinaryView,
    start_addr: u64,
    instr: &Instruction,
    offsets: &ConstantOffsets,
    buf: &[u8],
    relocations: &[Range<u64>],
    include_operands: bool,
) -> Result<OwnedPattern, SignatureError> {
    let mut pattern = buf.into_iter().map(|x| Some(*x)).collect::<OwnedPattern>();

    #[allow(unused_parens)]
    if instr.is_invalid()
        || matches!(
            instr.code(),
            (DeclareByte | DeclareWord | DeclareDword | DeclareQword)
        )
    {
        Err(SignatureError::InvalidInstruction)?
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

    // 0x10000000 constants here are what iced-x86 bases its disassembly on.

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

    let start_addr = start_addr as usize;
    for relocation in relocations {
        if (start_addr..(start_addr + instr.len())).contains(&(relocation.start as usize)) {
            let start_offset = relocation.start as usize - start_addr;
            let end_offset = relocation.end as usize - start_addr;
            for x in start_offset..end_offset {
                pattern[x] = None;
            }
        }
    }

    Ok(pattern)
}

fn find_patterns<'a>(
    code_segments: &'a [(u64, Vec<u8>)],
    pattern: Pattern<'a>,
) -> impl ParallelIterator<Item = u64> + 'a {
    fn find_patterns_internal<'a>(
        region: &'a [u8],
        pattern: Pattern<'a>,
    ) -> impl Iterator<Item = usize> + 'a {
        PatternSearcher::new(region, pattern)
    }

    code_segments
        .par_iter()
        .map(|segment| {
            find_patterns_internal(&segment.1, pattern)
                .map(|x| x as u64 + segment.0)
                .par_bridge()
        })
        .flatten()
}

fn is_pattern_unique(code_segments: &[(u64, Vec<u8>)], pattern: Pattern) -> bool {
    let iter = find_patterns(code_segments, pattern);

    let count = AtomicUsize::new(0);

    iter.find_any(|_| {
        count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        count.load(std::sync::atomic::Ordering::Relaxed) > 1
    })
    .is_none()
}

fn create_pattern_internal_binarysearch(
    bv: &BinaryView,
    addr: u64,
    data: &[(u64, Vec<u8>)],
    include_operands: bool,
) -> Result<OwnedPattern, SignatureError> {
    log::info!("creating pattern for address {:#04X}", addr);
    let time = SystemTime::now();

    let mut formatter = NasmFormatter::new();
    formatter.options_mut().set_rip_relative_addresses(true);

    let relocations = bv.relocation_ranges();

    let max_size = get_maximum_signature_size();

    let mut current_offset = 0u64;
    let mut current_buffer = vec![0u8; MAX_INSTRUCTION_LENGTH as usize];
    let mut current_pattern = OwnedPattern::default();
    let mut instr_offsets = vec![];

    let Some(start_segment) = bv.segment_at(addr as u64) else {
        Err(SignatureError::InvalidSegment)?
    };

    let data_segment = data
        .iter()
        .find(|segment| segment.0 == start_segment.address_range().start)
        .ok_or(SignatureError::InvalidSegment)?;

    #[cfg(debug_assertions)]
    log::info!("max sig size: {max_size}");

    loop {
        let instr_addr = addr + current_offset;
        let instr_addr_rel = addr + current_offset - start_segment.address_range().start;

        let max_size = std::cmp::min(
            max_size,
            data_segment.1.len() as u64 - (instr_addr - data_segment.0),
        );

        current_buffer[..std::cmp::min(max_size, MAX_INSTRUCTION_LENGTH) as usize].copy_from_slice(
            &data_segment.1[instr_addr_rel as usize
                ..instr_addr_rel as usize
                    + std::cmp::min(max_size, MAX_INSTRUCTION_LENGTH) as usize],
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

        let instr_pattern = get_instruction_pattern(
            bv,
            addr + current_offset,
            &instr,
            &offsets,
            instr_bytes,
            &relocations,
            include_operands,
        )?;

        #[cfg(debug_assertions)]
        log::info!(
            "{}: {}",
            instr_string,
            RustPattern(Cow::Borrowed(&instr_pattern))
        );

        if current_offset + instr.len() as u64 >= max_size {
            break;
        }

        // check that we are not crossing function boundaries
        // the range we were in at the start is still the same range as we are currently scanning
        if !bv.functions_containing(addr as u64).iter().any(|func| {
            func.address_ranges().iter().any(|range| {
                range.start <= addr && range.end >= (instr_addr + instr.len() as u64) as u64
            })
        }) {
            break;
        }

        current_pattern.extend(&instr_pattern);
        instr_offsets.push((current_offset, instr.len()));

        current_offset += instr.len() as u64;
    }

    let ((_, _), (unique_instr, _)) =
        binary_search((0, ()), (instr_offsets.len() as _, ()), |instr| {
            let instr = instr_offsets[instr];
            let pat = &current_pattern[0..instr.0 as usize + instr.1];

            #[cfg(debug_assertions)]
            log::info!("{}", RustPattern(Cow::Borrowed(&pat.to_vec())));

            match is_pattern_unique(&data, pat) {
                false => Direction::Low(()),
                true => Direction::High(()),
            }
        });

    let instr = instr_offsets[unique_instr.clamp(0, instr_offsets.len() - 1)];

    current_pattern.drain(instr.0 as usize + instr.1..);

    while let Some(x) = current_pattern.last()
        && x.is_none()
    {
        current_pattern.pop();
    }

    log::info!(
        "binsearch created pattern in {}ms",
        SystemTime::now().duration_since(time).unwrap().as_millis()
    );

    Ok(current_pattern)
}

fn create_pattern_internal(
    bv: &BinaryView,
    addr: u64,
    data: &[(u64, Vec<u8>)],
    include_operands: bool,
) -> Result<OwnedPattern, SignatureError> {
    log::info!("creating pattern for address {:#04X}", addr);
    let time = SystemTime::now();

    let mut formatter = NasmFormatter::new();
    formatter.options_mut().set_rip_relative_addresses(true);

    let relocations = bv.relocation_ranges();

    let mut current_offset = 0u64;
    let mut current_buffer = vec![0u8; MAX_INSTRUCTION_LENGTH as usize];
    let mut current_pattern = OwnedPattern::default();
    let mut pattern_unique = false;
    let max_size = get_maximum_signature_size();

    let Some(start_segment) = bv.segment_at(addr as u64) else {
        Err(SignatureError::InvalidSegment)?
    };

    let data_segment = data
        .iter()
        .find(|segment| segment.0 == start_segment.address_range().start)
        .ok_or(SignatureError::InvalidSegment)?;

    #[cfg(debug_assertions)]
    log::info!("max sig size: {max_size}");

    while !pattern_unique {
        let instr_addr = addr + current_offset;
        let instr_addr_rel = addr + current_offset - start_segment.address_range().start;

        let max_size = std::cmp::min(
            max_size,
            data_segment.1.len() as u64 - (instr_addr - data_segment.0),
        );

        current_buffer[..std::cmp::min(max_size, MAX_INSTRUCTION_LENGTH) as usize].copy_from_slice(
            &data_segment.1[instr_addr_rel as usize
                ..instr_addr_rel as usize
                    + std::cmp::min(max_size, MAX_INSTRUCTION_LENGTH) as usize],
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

        let instr_pattern = get_instruction_pattern(
            bv,
            addr + current_offset,
            &instr,
            &offsets,
            instr_bytes,
            &relocations,
            include_operands,
        )?;

        #[cfg(debug_assertions)]
        log::info!(
            "{}: {}",
            instr_string,
            RustPattern(Cow::Borrowed(&instr_pattern))
        );

        if current_offset + instr.len() as u64 >= max_size {
            break;
        }

        // check that we are not crossing function boundaries
        // the range we were in at the start is still the same range as we are currently scanning
        if !bv.functions_containing(addr as u64).iter().any(|func| {
            func.address_ranges().iter().any(|range| {
                range.start <= addr && range.end >= (instr_addr + instr.len() as u64) as u64
            })
        }) {
            break;
        }

        current_pattern.extend(&instr_pattern);

        current_offset += instr.len() as u64;
        pattern_unique = is_pattern_unique(&data, &current_pattern);
    }

    while let Some(x) = current_pattern.last()
        && x.is_none()
    {
        current_pattern.pop();
    }

    log::info!(
        "created pattern in {}ms",
        SystemTime::now().duration_since(time).unwrap().as_millis()
    );

    Ok(current_pattern)
}

fn create_pattern(bv: &BinaryView, addr: u64) -> Result<OwnedPattern, SignatureError> {
    let include_operands = get_include_operands();
    let data = get_code(bv);

    #[cfg(debug_assertions)]
    {
        let pattern = create_pattern_internal(bv, addr, &data, include_operands);
        let binsearch_pattern =
            create_pattern_internal_binarysearch(bv, addr, &data, include_operands);

        let _ = pattern
            .as_ref()
            .map(|pat| log::info!("{}", RustPattern(Cow::Borrowed(&pat))));

        let _ = binsearch_pattern
            .as_ref()
            .map(|pat| log::info!("{}", RustPattern(Cow::Borrowed(&pat))));

        if pattern.as_ref().unwrap() != binsearch_pattern.as_ref().unwrap() {
            log::error!("patterns dont match :(((");
        }
    }

    let pattern = if get_binary_search() {
        create_pattern_internal_binarysearch(bv, addr, &data, include_operands)
    } else {
        create_pattern_internal(bv, addr, &data, include_operands)
    };

    let pattern = if !include_operands && matches!(pattern, Err(SignatureError::NotUnique(_))) {
        log::warn!("unable to find a unique pattern that didn't include operands. trying again with operands!");
        if get_binary_search() {
            create_pattern_internal_binarysearch(bv, addr, &data, true)
        } else {
            create_pattern_internal(bv, addr, &data, true)
        }
    } else {
        pattern
    };

    if pattern
        .as_ref()
        .is_ok_and(|pat| !is_pattern_unique(&data, &pat))
    {
        log::error!("signature not unique, cannot proceed!");
        return Err(SignatureError::NotUnique(
            pattern.map_or(0u64, |pat| pat.len() as u64),
        ));
    }

    pattern
}

fn emit_result(contents: String) {
    log::info!("{}", &contents);
    if let Err(e) = set_clipboard_contents(contents) {
        log::error!("unable to copy to clipboard: {}", e);
    }
}

fn set_clipboard_contents(contents: String) -> Result<(), Box<dyn std::error::Error>> {
    let mut ctx: clipboard::ClipboardContext = clipboard::ClipboardProvider::new()?;

    ctx.set_contents(contents)
}

fn get_clipboard_contents() -> Result<String, Box<dyn std::error::Error>> {
    let mut ctx: clipboard::ClipboardContext = clipboard::ClipboardProvider::new()?;

    ctx.get_contents()
}

fn get_maximum_signature_size() -> u64 {
    Settings::new().get_integer("coolsigmaker.maximum_size")
}

fn get_include_operands() -> bool {
    Settings::new().get_bool("coolsigmaker.include_operands")
}

fn get_binary_search() -> bool {
    Settings::new().get_bool("coolsigmaker.binary_search")
}

fn get_signature_type() -> SignatureType {
    SignatureType::from_str(Settings::new().get_string("coolsigmaker.sig_type").as_str())
        .map_err(|_| {
            log::error!("invalid value for coolsigmaker.sig_type! falling back to default!")
        })
        .unwrap_or(SignatureType::IDATwo)
}

fn register_settings() {
    fn register_setting<T>(
        settings: &Settings,
        name: &str,
        title: &str,
        description: &str,
        typ: &str,
        default: T,
    ) where
        T: core::fmt::Display,
    {
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

        settings.register_setting_json(name, &properties);
    }

    fn register_enum_setting<T>(settings: &Settings, name: &str, title: &str, description: &str)
    where
        T: Display + EnumMessage + VariantNames + IntoEnumIterator + Default,
    {
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

        settings.register_setting_json(name, &properties);
    }

    let settings = Settings::new();

    settings.register_group("coolsigmaker", "CoolSigMaker");

    register_setting::<bool>(&settings, "coolsigmaker.include_operands", "Include Operands", "Include immediate operands that aren't memory-relative or relocated when creating signatures. This results in smaller, but potentially more fragile, signatures. If no unique signature can be generated without operands, we fall back to including them.", "boolean", false);

    register_setting::<bool>(&settings, "coolsigmaker.binary_search", "Use Binary Search", "Use a binary search to determine instruction uniqueness. For small binaries, this will be slower than the default, while for bigger binaries it might be faster. It starts scanning at half the maximum signature size. There is no heuristic implemented to automatically determine this yet.", "boolean", false);

    register_setting::<u64>(
        &settings,
        "coolsigmaker.maximum_size",
        "Maximum Signature Size",
        "The maximum size the signature will accumulate before giving up.",
        "number",
        64,
    );

    register_enum_setting::<SignatureType>(
        &settings,
        "coolsigmaker.sig_type",
        "Signature Type",
        "The signature type to use for creating and finding signatures",
    );
}

#[test]
fn test_patterns() {
    // .clone() code smell..... but this eliminates calling .unwrap() and then comparing by reference, whatever.
    let test_pattern = vec![Some(0xE9), None, None, None, None, Some(0x90), Some(0x90)];

    assert_eq!(
        OwnedPattern::from_signature(String::from("E9 ? ? ? ? 90 90"), SignatureType::IDAOne),
        Some(test_pattern.clone())
    );

    assert_eq!(
        OwnedPattern::from_signature(String::from("E9 ?? ?? ?? ?? 90 90"), SignatureType::IDATwo),
        Some(test_pattern.clone())
    );

    assert_eq!(
        OwnedPattern::from_signature(
            String::from("0xE9, _, _, _, _, 0x90, 0x90"),
            SignatureType::Rust
        ),
        Some(test_pattern.clone())
    );

    assert_eq!(
        OwnedPattern::from_signature(
            String::from(r#""\xE9\x00??\x00\x90\x90" "x????xx""#),
            SignatureType::CStr
        ),
        Some(test_pattern.clone())
    );
}

impl AddressCommand for SigMakerCommand {
    fn action(&self, bv: &BinaryView, addr: u64) {
        match create_pattern(bv, addr as _) {
            Ok(pattern) => {
                let pattern: Box<dyn core::fmt::Display> = match get_signature_type() {
                    SignatureType::IDAOne => Box::new(IDAOnePattern(Cow::Owned(pattern))),
                    SignatureType::IDATwo => Box::new(IDATwoPattern(Cow::Owned(pattern))),
                    SignatureType::Rust => Box::new(RustPattern(Cow::Owned(pattern))),
                    SignatureType::CStr => Box::new(CStrPattern(Cow::Owned(pattern))),
                };

                emit_result(format!("{}", pattern));
            }
            Err(e) => {
                log::error!("unable to create pattern! {e}");
            }
        }
    }

    fn valid(&self, bv: &BinaryView, addr: u64) -> bool {
        // there is a function at the specified address. the pattern creation code will make sure we stay within a valid function.
        !bv.functions_containing(addr).is_empty()
    }
}

impl Command for SigFinderCommand {
    fn action(&self, bv: &BinaryView) {
        let Ok(sig) = get_clipboard_contents() else {
            log::error!("unable to get signature from clipboard!");
            return;
        };

        let time = SystemTime::now();

        let data = get_code(bv);

        let Some(pattern) = OwnedPattern::from_signature(sig, get_signature_type()) else {
            log::error!("failed to parse pattern.");
            return;
        };

        find_patterns(&data, &pattern)
            .for_each(|occurrence| log::info!("found signature at {:#04X}", occurrence));

        log::info!(
            "scan finished in {}ms.",
            SystemTime::now().duration_since(time).unwrap().as_millis()
        );
    }

    fn valid(&self, _bv: &BinaryView) -> bool {
        true
    }
}

#[no_mangle]
pub extern "C" fn CorePluginInit() -> bool {
    // Due to a breaking change in binaryninja-api, you will need to edit this line depending on which version you are building for.

    // For dev branch:
    binaryninja::logger::Logger::new("coolsigmaker")
        .with_level(log::LevelFilter::Info)
        .init();

    // For stable branch:
    // binaryninja::logger::init(log::LevelFilter::Info).unwrap();

    // And uncomment this. Sorry for the inconvenience.
    // compile_error!("sadly, due to a breaking change in the api crate, you will need to make a change to the code above this error.");

    // TODO: (maybe) if signature not found, maybe go back a few instructions and attempt to create a signature with an offset.
    // TODO: introduce a setting for "dumb" searches, where we also search non-executable segments for uniqueness, incase the user doesn't want to check the segments before scanning them.
    // TODO: make a fancy regex to distinguish signature types automagically (without accidental mismatches occurring)

    log::info!("binja_coolsigmaker by unknowntrojan loaded!");
    log::info!("say hello to the little ninja in your binja");

    #[cfg(debug_assertions)]
    std::panic::set_hook(Box::new(|info| {
        let string = format!(
            "{}\n{:#?}\n{}",
            info,
            info,
            std::backtrace::Backtrace::force_capture()
        );

        // #[cfg(debug_assertions)]
        let _ = std::fs::write("E:\\log.txt", &string);

        log::info!("{}", &string);
    }));

    register_settings();

    command::register_command_for_address(
        "CSM - Create Signature from Address",
        "Creates a Signature from the currently selected address",
        SigMakerCommand {},
    );

    command::register_command(
        "CSM - Find Signature",
        "Finds a signature in the binary.",
        SigFinderCommand {},
    );

    true
}
