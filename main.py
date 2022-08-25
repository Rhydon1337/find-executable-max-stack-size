import idautils
import idaapi
import idc


class FunctionTree(object):
    def __init__(self, function_start_address: int):
        self.is_root = False
        self.children = set()
        self.function_start_address = function_start_address
        self.max_stack_size = 0


def find_function_max_stack_size(function_tree) -> int:
    nodes_stack = []

    current_node = function_tree

    max_stack_size = idc.get_frame_size(function_tree.function_start_address)

    parents = set()
    parents.add(current_node.function_start_address)

    nodes_stack.append((parents, current_node, max_stack_size))

    while len(nodes_stack) > 0:
        parents, current_node, temp_max_stack_size = nodes_stack.pop()
        for child in current_node.children:
            if child.function_start_address in parents:
                # Found recursion - skipping
                continue

            parents = parents.copy()
            parents.add(child.function_start_address)
            nodes_stack.append((parents, child, temp_max_stack_size + idc.get_frame_size(child.function_start_address)))

        max_stack_size = max(max_stack_size, temp_max_stack_size)

    return max_stack_size


def get_root_functions() -> [FunctionTree]:
    all_functions = {}

    for function_start in idautils.Functions():
        if function_start in all_functions:
            function_tree = all_functions[function_start]
        else:
            function_tree = FunctionTree(function_start)
            all_functions[function_start] = function_tree

        number_of_iterations = 0
        xrefs = idautils.CodeRefsTo(function_start, False)
        for xref in xrefs:
            if idaapi.get_func(xref.real) is None:
                continue

            number_of_iterations += 1

            xref_function_start = idaapi.get_func(xref.real).start_ea

            if xref_function_start in all_functions:
                xref_function_tree = all_functions[xref_function_start]
            else:
                xref_function_tree = FunctionTree(xref_function_start)
                all_functions[xref_function_start] = xref_function_tree

            if xref_function_tree.function_start_address != function_tree.function_start_address:
                xref_function_tree.children.add(function_tree)

        if number_of_iterations == 0:
            function_tree.is_root = True

    return [function_tree for function_start, function_tree in all_functions.items() if function_tree.is_root]


def print_function(function_address, max_stack_size):
    function_name = idaapi.get_func_name(function_address)
    if len(function_name) == 0:
        print(
            f"Root function address is: {hex(function_address)}, "
            f"max stack size is: {hex(max_stack_size)}")
    else:
        print(
            f"Root function name is: {function_name}, "
            f"address: {hex(function_address)}, "
            f"max stack size is: {hex(max_stack_size)}")


def main():
    print("Finding max stack size")
    root_functions = get_root_functions()

    function_with_max_stack_size = root_functions[0]
    for root_function in root_functions:
        root_function.max_stack_size = find_function_max_stack_size(root_function)
        print_function(root_function.function_start_address, root_function.max_stack_size)

        function_with_max_stack_size = max(function_with_max_stack_size, root_function,
                                           key=lambda function: function.max_stack_size)

    print("----------------------------------------------------------------------------------------------------------")
    print("FUNCTION WITH MAX STACK SIZE")
    print_function(function_with_max_stack_size.function_start_address, function_with_max_stack_size.max_stack_size)
    print("----------------------------------------------------------------------------------------------------------")


if __name__ == '__main__':
    main()
