def parse_elf(file_path):
    with open(file_path, "rb") as f:
        header = f.read(20)

    if len(header) < 20 or header[:4] != b"\x7fELF":
        print("Not a valid ELF file")
        return

    elf_class = header[4]
    endian = header[5]

    print("ELF file detected")
    print("Architecture class:", {
        1: "32-bit",
        2: "64-bit"
    }.get(elf_class, "Unknown"))

    print("Endianness:", {
        1: "Little Endian",
        2: "Big Endian"
    }.get(endian, "Unknown"))


if __name__ == "__main__":
    print("FirmSight ELF Parser")
