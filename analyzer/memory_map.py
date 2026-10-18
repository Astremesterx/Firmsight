from elftools.elf.elffile import ELFFile


def get_permissions(flags):
    read = "R" if flags & 4 else "-"
    write = "W" if flags & 2 else "-"
    execute = "X" if flags & 1 else "-"
    return read + write + execute


def extract_memory_map(file_path):
    with open(file_path, "rb") as f:
        elf = ELFFile(f)

        print("FirmSight Memory Map")
        print("-" * 50)

        for segment in elf.iter_segments():
            if segment["p_type"] == "PT_LOAD":
                start = segment["p_vaddr"]
                size = segment["p_memsz"]
                end = start + size
                permissions = get_permissions(segment["p_flags"])

                print(f"Address range: 0x{start:x} - 0x{end:x}")
                print(f"Memory size:   {size} bytes")
                print(f"Permissions:   {permissions}")
                print("-" * 50)


if __name__ == "__main__":
    print("FirmSight Memory Map Extractor")
    