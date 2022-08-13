import pefile


def get_pe_base_entry_point_offset(pe_file_data):
    pe_file = pefile.PE(data=pe_file_data)
    virtual_entry_point = pe_file.OPTIONAL_HEADER.AddressOfEntryPoint
    for section in pe_file.sections:
        if section.name == ".text":
            return virtual_entry_point - section.VirtualAddress + section.PointerToRawData
