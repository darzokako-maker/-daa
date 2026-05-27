use std::env;
use std::fs::File;
use std::io::Read;
use object::{Object, ObjectSection};
use zydis::{Decoder, Formatter, FormatterStyle, MachineMode, StackWidth};
use colored::*;

fn main() {
    println!("{}", "===================================================".green().bold());
    println!("{}", "       NEXTGEN-IDA: ADVANCED REVERSE ENGINEERING CORE  ".green().bold());
    println!("{}", "===================================================".green().bold());

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        return;
    }

    let file_path = &args[1];
    let search_pattern = if args.len() > 2 { Some(&args[2]) } else { None };

    println!("[+] Loading Target File: {}", file_path.cyan());
    
    let mut file = match File::open(file_path) {
        Ok(f) => f,
        Err(e) => {
            println!("{} {}: {}", "[-]".red(), "Failed to open file".red(), e);
            return;
        }
    };

    // Bellek ömrü (lifetime) hatasını önlemek için ana gövdede tutulan buffer
    let mut buffer = Vec::new();
    if let Err(e) = file.read_to_end(&mut buffer) {
        println!("{} {}: {}", "[-]".red(), "Failed to read file".red(), e);
        return;
    }

    let obj_file = match object::File::parse(&*buffer) {
        Ok(obj) => obj,
        Err(e) => {
            println!("{} {}: {}", "[-]".red(), "Failed to parse binary format".red(), e);
            return;
        }
    };

    println!("[+] Format Detected: {:?}", obj_file.format());
    println!("[+] Architecture: {:?}", obj_file.architecture());
    println!("[+] Entry Point: 0x{:X}", obj_file.entry());

    let (machine_mode, stack_width) = match obj_file.architecture() {
        object::Architecture::X86_64 => (MachineMode::LONG_64, StackWidth::_64),
        object::Architecture::I386 => (MachineMode::LEGACY_32, StackWidth::_32),
        _ => {
            println!("{}", "[-] Unsupported architecture for Zydis module (x86/x64 only).".red());
            return;
        }
    };

    // 1. DISASSEMBLER MODÜLÜ (Zydis v4.x Güncel API Yapısı)
    println!("\n{}", "[*] Analyzing .text / Code Section...".bold().blue());
    if let Some(text_section) = obj_file.section_by_name(".text") {
        if let Ok(code_data) = text_section.data() {
            println!("[+] Found .text section (Size: {} bytes)", code_data.len().to_string().green());
            
            let decoder = Decoder::new(machine_mode, stack_width).unwrap();
            
            // ÇÖZÜM 1: unwrap() ifadesi kaldırıldı, çünkü artık doğrudan Formatter yapısı dönüyor.
            let formatter = Formatter::new(FormatterStyle::INTEL);
            
            let mut offset = 0;
            let mut count = 0;
            let base_address = text_section.address();

            while offset < code_data.len() && count < 20 {
                let current_slice = &code_data[offset..];
                
                if let Ok(Some(instruction)) = decoder.decode_first(current_slice) {
                    
                    // ÇÖZÜM 2: OutputBuffer ve .clear() karmaşasını tamamen baypas eden,
                    // her döngüde otomatik olarak sıfırlanan 256 byte'lık temiz bir ham buffer dizisi.
                    let mut text_buffer = [0u8; 256];
                    
                    if formatter.format_instruction(
                        &instruction,
                        &instruction.operands()[..instruction.operand_count as usize],
                        &mut text_buffer[..],
                        Some(base_address + offset as u64),
                        None
                    ).is_ok() {
                        // Byte dizisini stringe dönüştürüp null terminatörleri (\0) kırpıyoruz
                        if let Ok(asm_string) = std::str::from_utf8(&text_buffer) {
                            let va = base_address + offset as u64;
                            println!("  0x{:016X}:  {}", va, asm_string.trim_matches('\0'));
                        }
                    }
                    
                    offset += instruction.length as usize;
                    count += 1;
                } else {
                    offset += 1; 
                }
            }
            if code_data.len() > offset {
                println!("  ... (and {} more bytes optimized for lazy-loading) ...", code_data.len() - offset);
            }
        }
    } else {
        println!("{}", "[-] Warning: .text section not found. Analysis aborted.".yellow());
    }

    // 2. GELİŞMİŞ PATTERN / SIGNATURE SCANNER MODÜLÜ
    if let Some(pattern_str) = search_pattern {
        println!("\n{}", "[*] Initializing Advanced Pattern Scan Engine...".bold().blue());
        if let Some(pattern_bytes) = parse_hex_pattern(pattern_str) {
            println!("[+] Searching for signature: {:?}", pattern_str.cyan());
            
            let mut found_offsets = Vec::new();
            for section in obj_file.sections() {
                if section.kind() == object::SectionKind::Text {
                    if let Ok(data) = section.data() {
                        if let Some(offsets) = scan_pattern(data, &pattern_bytes) {
                            for off in offsets {
                                found_offsets.push(section.address() + off as u64);
                            }
                        }
                    }
                }
            }

            if found_offsets.is_empty() {
                println!("{}", "[-] Pattern NOT found in any executable segment.".red().bold());
            } else {
                for addr in found_offsets {
                    println!("  {} Found Offset / Signature Match at: {}", "[TARGET ACQUIRED]".green().bold(), format!("0x{:X}", addr).green().bold());
                }
            }
        } else {
            println!("{}", "[-] Invalid hex pattern format.".red());
        }
    }
}

fn print_usage() {
    println!("{}", "[-] Usage: nextgen-ida <path_to_binary> [pattern_hex]".yellow());
}

fn parse_hex_pattern(pattern: &str) -> Option<Vec<Option<u8>>> {
    let mut result = Vec::new();
    for token in pattern.split_whitespace() {
        if token == "?" || token == "??" {
            result.push(None);
        } else {
            match u8::from_str_radix(token, 16) {
                Ok(byte) => result.push(Some(byte)),
                Err(_) => return None,
            }
        }
    }
    Some(result)
}

fn scan_pattern(data: &[u8], pattern: &[Option<u8>]) -> Option<Vec<usize>> {
    let mut matches = Vec::new();
    if pattern.is_empty() || data.len() < pattern.len() {
        return None;
    }

    for i in 0..=(data.len() - pattern.len()) {
        let mut is_match = true;
        for (j, pattern_byte) in pattern.iter().enumerate() {
            if let Some(b) = pattern_byte {
                if data[i + j] != *b {
                    is_match = false;
                    break;
                }
            }
        }
        if is_match {
            matches.push(i);
        }
    }

    if matches.is_empty() { None } else { Some(matches) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_pattern_matching() {
        let raw_data = vec![0x90, 0x55, 0x48, 0x89, 0xE5, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x5D, 0xC3];
        let pattern = parse_hex_pattern("48 89 E5").unwrap();
        let result = scan_pattern(&raw_data, &pattern);
        assert_eq!(result, Some(vec![2]));
    }
}
