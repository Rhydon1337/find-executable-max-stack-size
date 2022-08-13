import argparse

from stack_parser import find_maximum_stack_size
from windows_pe import get_pe_base_entry_point_offset

FILES = {
    "PE": get_pe_base_entry_point_offset
}


def main():
    parser = argparse.ArgumentParser(description='Find maximum stack size usage for x86 and x86_64 find-max-stack')
    parser.add_argument('file_type', type=str, help='ELF or PE or Binary')
    parser.add_argument('file_path', type=str, help='The path to the executable')
    parser.add_argument('--entry_point', type=int, default=0, help='Only for binary type - offset to the entry point')

    args = parser.parse_args()
    with open(args.file_path, "rb") as file:
        file_data = file.read()

    if args.file_type == "Binary":
        entry_point = args.entry_point
    else:
        entry_point = FILES[args.file_type](file_data)

    max_stack_size = find_maximum_stack_size(file_data, entry_point)
    print(f"The maximum stack size is: 0x{hex(max_stack_size)}")


if __name__ == '__main__':
    main()
