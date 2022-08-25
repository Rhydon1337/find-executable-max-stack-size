import idautils
import idaapi
import idc


def get_root_functions():
    root_functions = set()

    def find_root_functions(function_start_address):
        xrefs = CodeRefsTo(function_start_address, 0)

        number_of_iterations = 0
        for xref in xrefs:
            number_of_iterations += 1
            find_root_functions(get_func(xref.real).start_ea)

        if number_of_iterations == 0:
            root_functions.add(function_start_address)
        else:
            root_functions.discard(function_start_address)

    for function_start in Functions():
        find_root_functions(function_start)

    return root_functions


def get_function_max_stack_size(function_start_address):
    xrefs = CodeRefsFrom(function_start_address, 0)

    overall_size = 0
    for xref in xrefs:
        overall_size += get_function_max_stack_size(get_func(xref.real).start_ea)

    return get_frame_size(function_start_address) + overall_size


def main():
    print("Finding max stack size")
    root_functions = get_root_functions()
    for function in root_functions:
        stack_size = get_function_max_stack_size(function)
        print(f"Root function address is: {hex(function)}, stack size is: {hex(stack_size)}")


if __name__ == '__main__':
    main()
