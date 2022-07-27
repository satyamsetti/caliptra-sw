/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main entrypoint for Caliptra Emulator.

--*/

mod cpu;
mod csr_file;
mod device;
mod emu_ctrl;
mod exception;
mod instr;
mod macros;
mod mem;
mod ram;
mod rom;
mod types;
mod uart;
mod xreg_file;

use crate::cpu::{Cpu, StepAction};
use crate::emu_ctrl::EmuCtrl;
use crate::ram::Ram;
use crate::rom::Rom;
use crate::uart::Uart;
use clap::Parser;
use std::fs::File;
use std::io;
use std::io::Read;
use std::path::Path;
use std::process::exit;

/// Caliptra emulator
#[derive(Parser, Debug)]
#[clap(version, about, long_about = None)]
struct Args {
    /// ROM binary path
    #[clap(short, long, value_parser)]
    rom: String,

    /// Execution trace
    #[clap(short, long, value_parser)]
    trace: Option<String>,
}

fn main() -> io::Result<()> {
    const ROM_SIZE: usize = 32 * 1024;
    const ICCM_SIZE: usize = 128 * 1024;
    const DCCM_SIZE: usize = 128 * 1024;

    let args = Args::parse();
    if !Path::new(&args.rom).exists() {
        println!("ROM File '{}' does not exists", args.rom);
        exit(-1);
    }

    let mut rom = File::open(args.rom)?;
    let mut buffer = Vec::new();
    rom.read_to_end(&mut buffer)?;

    if buffer.len() > ROM_SIZE {
        println!("ROM File Size must not exceed {} bytes", ROM_SIZE);
        exit(-1);
    }

    let mut cpu = Cpu::new();
    let rom = Rom::new("ROM", 0x0000_0000, buffer);
    let iccm = Ram::new("ICCM", 0x4000_0000, vec![0; ICCM_SIZE]);
    let dccm = Ram::new("DCCM", 0x5000_0000, vec![0; DCCM_SIZE]);
    let uart = Uart::new("UART0", 0x2000_0000);
    let ctrl = EmuCtrl::new("EMU_CTRL", 0x3000_0000);

    if !cpu.attach_dev(Box::new(rom)) {
        println!("Failed to attach ROM.");
        exit(-1);
    }

    if !cpu.attach_dev(Box::new(iccm)) {
        println!("Failed to attach ICCM.");
        exit(-1);
    }

    if !cpu.attach_dev(Box::new(dccm)) {
        println!("Failed to attach DCCM.");
        exit(-1);
    }

    if !cpu.attach_dev(Box::new(uart)) {
        println!("Failed to attach UART.");
        exit(-1);
    }

    if !cpu.attach_dev(Box::new(ctrl)) {
        println!("Failed to attach Emulator Control.");
        exit(-1);
    }

    loop {
        match cpu.step(None) {
            StepAction::Continue => continue,
            _ => break,
        }
    }

    Ok(())
}