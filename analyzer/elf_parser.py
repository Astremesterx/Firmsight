import struct


def parse_elf(file_path):
    with open(file_path, "rb") as f:
        header = f.read(20)

    if header[:4] != b"\x7fELF":
        print("Not a valid ELF file")
        return

    elf_class = header[4]
    endian = header[5]

    print("ELF file detected")

    if elf_class == 1:
        print("Architecture class: 32-bit")
    elif elf_class == 2:
        print("Architecture class: 64-bit")
    else:
        print("Unknown architecture class")

    if endian == 1:
        print("Endianness: Little Endian")
    elif endian == 2:
        print("Endianness: Big Endian")
    else:
        print("Unknown endianness")


if __name__ == "__main__":
    print("FirmSight ELF Parser")