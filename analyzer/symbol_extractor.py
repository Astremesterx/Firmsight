from elftools.elf.elffile import ELFFile


def extract_symbols(file_path):
    with open(file_path, "rb") as f:
        elf = ELFFile(f)

        found_symbols = False

        for section in elf.iter_sections():
            if section.name in (".symtab", ".dynsym"):
                for symbol in section.iter_symbols():
                    if symbol.name:
                        print(symbol.name)
                        found_symbols = True

        if not found_symbols:
            print("No symbols found. The ELF may be stripped.")


if __name__ == "__main__":
    print("FirmSight ELF Symbol Extractor")
