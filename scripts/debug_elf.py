#!/usr/bin/env python3
"""Debug: Check bytecode size and structure"""

from pathlib import Path
from struct import unpack

# Check generated ELF
elf_path = Path('samples/advanced_vm.elf')
if elf_path.exists():
    data = elf_path.read_bytes()
    print(f"ELF total size: {len(data)} bytes")
    
    # Read entry point (offset 24 in ELF32 header, 4 bytes)
    entry_point = unpack('<I', data[24:28])[0]
    print(f"Entry point: 0x{entry_point:08x}")
    
    # Read program header offset (offset 28, 4 bytes)
    phoff = unpack('<I', data[28:32])[0]
    print(f"Program header offset: {phoff}")
    
    # Read section header offset (offset 32, 4 bytes)
    shoff = unpack('<I', data[32:36])[0]
    print(f"Section header offset: 0x{shoff:08x} ({shoff})")
    
    # Read first section header (should be .text at offset 52)
    # Section headers are 40 bytes each, starting at shoff
    # For .text, we look at section 1
    sh_text_off = shoff + (1 * 40)
    
    if sh_text_off + 40 <= len(data):
        sh_text = data[sh_text_off:sh_text_off + 40]
        sh_name = unpack('<I', sh_text[0:4])[0]
        sh_type = unpack('<I', sh_text[4:8])[0]
        sh_flags = unpack('<I', sh_text[8:12])[0]
        sh_addr = unpack('<I', sh_text[12:16])[0]
        sh_off = unpack('<I', sh_text[16:20])[0]
        sh_size = unpack('<I', sh_text[20:24])[0]
        
        print(f"\n.text section:")
        print(f"  Address: 0x{sh_addr:08x}")
        print(f"  File offset: {sh_off}")
        print(f"  Size: {sh_size} bytes")
        print(f"  Type: {sh_type} (1=PROGBITS)")
        print(f"  Flags: 0x{sh_flags:x} (6=ALLOC|EXECINSTR)")
        
        # Extract and analyze bytecode
        if sh_off + sh_size <= len(data):
            bytecode = data[sh_off:sh_off + sh_size]
            print(f"\nBytecode analysis:")
            print(f"  First 20 bytes: {' '.join(f'0x{b:02x}' for b in bytecode[:20])}")
            print(f"  Last 20 bytes: {' '.join(f'0x{b:02x}' for b in bytecode[-20:])}")
            
            # Count opcodes
            HALT = 0x00
            PUSH = 0x68
            
            halt_count = sum(1 for b in bytecode if b == HALT)
            push_count = sum(1 for b in bytecode if b == PUSH)
            
            print(f"  HALT count: {halt_count}")
            print(f"  PUSH count: {push_count}")
            print(f"  Non-zero bytes: {sum(1 for b in bytecode if b != 0)}")
else:
    print("ELF not found")
