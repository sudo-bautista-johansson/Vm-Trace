from pathlib import Path
from struct import pack

sample_dir = Path('samples')
sample_dir.mkdir(exist_ok=True)
path = sample_dir / 'sample_vm.elf'

bytecode = bytes([0x01, 0x02, 0x03, 0x04, 0x05])

# ELF32 little-endian header
ident = bytearray([0x7F, ord('E'), ord('L'), ord('F'), 1, 1, 1, 0]) + bytes(8)
header = pack('<HHIIIIIHHHHHH',
              2,      # e_type
              3,      # e_machine (EM_386)
              1,      # e_version
              0x1000, # e_entry
              0,      # e_phoff
              0x100,  # e_shoff
              0,      # e_flags
              52,     # e_ehsize
              0,      # e_phentsize
              0,      # e_phnum
              40,     # e_shentsize
              3,      # e_shnum
              1)      # e_shstrndx

shstrtab = b'\x00.shstrtab\x00.text\x00'
shstrtab_offset = 0x300
shstrtab_size = len(shstrtab)
text_offset = 0x200
text_addr = 0x1000
text_size = len(bytecode)

sh_null = bytes(40)
sh_shstrtab = pack('<IIIIIIIIII',
                    1,    # sh_name
                    3,    # sh_type = SHT_STRTAB
                    0,    # sh_flags
                    0,    # sh_addr
                    shstrtab_offset,
                    shstrtab_size,
                    0,
                    0,
                    1,
                    0)
sh_text = pack('<IIIIIIIIII',
               11,   # sh_name
               1,    # sh_type = SHT_PROGBITS
               5,    # sh_flags = SHF_ALLOC | SHF_EXECINSTR
               text_addr,
               text_offset,
               text_size,
               0,
               0,
               16,
               0)

content = bytearray(ident + header)
content += bytes(0x100 - len(content))
content += sh_null + sh_shstrtab + sh_text
if len(content) < text_offset:
    content += bytes(text_offset - len(content))
content += bytecode
if len(content) < shstrtab_offset:
    content += bytes(shstrtab_offset - len(content))
content += shstrtab

path.write_bytes(content)
print(f'Wrote sample ELF: {path.resolve()} size={len(content)} bytes')
