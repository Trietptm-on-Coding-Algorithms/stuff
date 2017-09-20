# -*- coding: utf-8 -*-

"""
to share between ida and pydbg.
we don't want any dependencies
"""


class api_summary_with_stacks:
    def __init__(self, to_addr, api_name, from_func_name):
        """
            @param: to_addr        : int    : return address of this api summary
            @param: api_name       : string : api name that truely hit breakpoint
            @param: from_func_name : string :
        """
        assert to_addr != 0

        self.to_addr = to_addr
        self.api_name = api_name
        self.from_func_name = from_func_name

        self.stacks_list = []
        self.param_str_list = []

        self.call_count = 0

    def __str__(self):
        """
        """
        return "to_addr: %.8X, api: %s, from_name: %s, call_count: %d, stacks_cnt: %d param_count: %d" % (self.to_addr, self.api_name, self.from_func_name, self.call_count, len(self.stacks_list), len(self.param_str_list))

    def lines(self):
        """
            @return: list : a list of strings
        """
        lines = [str(self)]
        lines.append("    stacks:")
        for stacks in self.stacks_list:
            lines.append("    stack:")
            for stack in stacks:
                lines.append("        %s" % str(stack))
        lines.append("    params:")
        for param_str in self.param_str_list:
            lines.append("        %s" % param_str)
        return lines


class api_summary_no_stacks:
    def __init__(self, api_name):
        """
        """
        self.api_name = api_name
        self.param_str_list = []

        self.call_count = 0

    def __str__(self):
        """
        """
        return "api: %s, call_count: %d, param_count: %d" % (self.api_name, self.call_count, len(self.param_str_list))

    def lines(self):
        """
            @return: list : a list of strings
        """
        lines = [str(self)]
        for param_str in self.param_str_list:
            lines.append("    %s" % param_str)
        return lines


class call_stack:
    def __init__(self, hex_context, from_addr, from_md_name, from_md_offset, to_addr, to_md_name, to_md_offset):
        """
        """
        self.hex_context = hex_context

        self.from_addr = from_addr
        self.from_md_name = from_md_name
        self.from_md_offset = from_md_offset
        self.from_func_name = None
        self.from_func_offset = None

        self.to_addr = to_addr
        self.to_md_name = to_md_name
        self.to_md_offset = to_md_offset
        self.to_func_name = None
        self.to_func_offset = None

    def __str__(self):
        """
        """
        if self.from_func_name is not None:
            # (7C91E81D)ntdll.dll._RtlSetCurrentDirectory_U@4+0000008F
            from_str = "(%.8X)%s.%s+%.8X" % (self.from_md_offset, self.from_md_name, self.from_func_name, self.from_func_offset)
        else:
            from_str = "(%.8X)%s.%.8X" % (self.from_md_offset, self.from_md_name, self.from_addr)

        if self.to_func_name is not None:
            to_str = "(%.8X)%s.%s+%.8X" % (self.to_md_offset, self.to_md_name, self.to_func_name, self.to_func_offset)
        else:
            to_str = "(%.8X)%s.%.8X" % (self.to_md_offset, self.to_md_name, self.to_addr)

        return "%s | %s" % (from_str, to_str)


def is_same_stacks(stacks_1, stacks_2):
    """
        @param: stacks_1 : list : a list of call_stack() objects
        @param: stacks_2 : list : a list of call_stack() objects
    """
    if len(stacks_1) != len(stacks_2):
        return False

    for i in range(len(stacks_1)):
        if stacks_1[i].to_addr != stacks_2[i].to_addr:
            return False

    return True


def has_stacks(stacks_list, stacks):
    """
        @param: stacks_list : list : a list of internal list, each internal list is a list of call_stack() objects
        @param: stacks      : list : a list of call_stack() objects
    """
    if len(stacks_list) == 0:
        return False

    for stacks_item in stacks_list:
        if is_same_stacks(stacks_item, stacks):
            return True

    return False


def is_stacks_has_None_md(stacks):
    """
        check if from_md_name or to_md_name of any stack in stacks is "None", meaning these stacsk went through "heap" or "stack"

        @param: stacks : list : a list of call_stack() object

        @return: bool :
               : None :

        !+ do not check to_md_name of last stack, which shall always be ""
        !+ it's "pickle loader"'s responsibility to check if stacks has None md.
    """
    for i in range(len(stacks) - 1):

        stack = stacks[i]
        if stack.to_md_name is None or stack.to_md_name == "":
            return True
        if stack.from_md_name is None or stack.from_md_name == "":
            return True

    return stacks[-1].from_md_name is None or stacks[-1].from_md_name == ""
