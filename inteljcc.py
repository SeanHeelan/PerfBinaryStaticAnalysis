#!/usr/bin/env python3
"""Find instances of jumps that meet the definition set out in [1] for
instructions that will not be placed into the DecodedICache.

[1] https://www.intel.com/content/dam/support/us/en/documents/processors/mitigations-jump-conditional-code-erratum.pdf
"""

from hashlib import new
import sys
from typing import List

from dataclasses import dataclass

import binaryninja
import capstone as cs
from capstone import x86_const as x86

md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
jcc_ids = set([
    x86.X86_INS_JAE,
    x86.X86_INS_JA,
    x86.X86_INS_JBE,
    x86.X86_INS_JB,
    x86.X86_INS_JCXZ,
    x86.X86_INS_JECXZ,
    x86.X86_INS_JE,
    x86.X86_INS_JGE,
    x86.X86_INS_JG,
    x86.X86_INS_JLE,
    x86.X86_INS_JL,
    x86.X86_INS_JMP,
    x86.X86_INS_JNE,
    x86.X86_INS_JNO,
    x86.X86_INS_JNP,
    x86.X86_INS_JNS,
    x86.X86_INS_JO,
    x86.X86_INS_JP,
    x86.X86_INS_JRCXZ,
    x86.X86_INS_JS,
])
macro_fusable_ids = set([
    x86.X86_INS_CMP, x86.X86_INS_TEST, x86.X86_INS_ADD,
    x86.X86_INS_SUB, x86.X86_INS_AND, x86.X86_INS_INC, x86.X86_INS_DEC])

@dataclass(frozen=True)
class IntelJCCErratumResult:
    """Represents an instance of a jump (or jump-like instruction, or
    macro-fused op+jump pair) that crosses a 32-byte boundary and thus
    will not be placed int he DecodedICache.
    """
    function_start_address: int
    loop_start_address: int
    jump_address: int

    def __str__(self):
        return f"Result(function=0x{self.function_start_address:08x}, " \
            f"jump=0x{self.jump_address:08x})"

def ins_matches_ret_conditions(
    ins: cs.CsInsn, addr: int, ins_len: int) -> bool:
    if ins.id != x86.X86_INS_RET:
        return False

    if addr + ins_len % 32 == 0:
        return True


def ins_matches_jcc_conditions(
        ins: cs.CsInsn, addr: int, ins_len: int,
        prev_ins: cs.CsInsn, prev_addr: int, prev_len: int) -> bool:
    if ins.id not in jcc_ids:
        return False

    # Ends on 32b boundary
    if addr + ins_len % 32 == 0:
        return True

    # Crosses 32b boundary
    for x in range(addr, addr+ins_len):
        if x % 32 == 0:
            return True

    # Check for macro-fusable op preceeding the JCC
    if prev_ins is None or prev_ins.id not in macro_fusable_ids:
        return False

    # Fusable op ends on 32b boundary
    if prev_addr + prev_len % 32 == 0:
        return True

    # Fusable op crosses on 32b boundary
    for x in range(prev_addr, prev_addr+prev_len):
        if x % 32 == 0:
            return True

    return False


def ins_matches_jmp_conditions(ins: cs.CsInsn, addr: int, ins_len: int) -> bool:
    if ins.id != x86.X86_INS_JMP:
        return False

    # Ends on 32b boundary
    if addr + ins_len % 32 == 0:
        return True

    # Crosses 32b boundary
    for x in range(addr, addr+ins_len):
        if x % 32 == 0:
            return True

    return False


def intel_jcc_erratum_analysis(
        func: binaryninja.Function) -> List[IntelJCCErratumResult]:
    rs = []
    prev_ins = prev_addr = prev_ins_len = None

    for _, addr in func.instructions:
        found = False
        ins_len = bv.get_instruction_length(addr)
        data = bv.read(addr, ins_len)

        inss = list(md.disasm(data, ins_len))
        if len(inss) != 1:
            raise Exception(
                f"Should be a single instruction, not {len(inss)}: {inss}")

        ins = inss[0]
        if ins_matches_ret_conditions(ins, addr, ins_len):
            found = True
        elif ins_matches_jmp_conditions(ins, addr, ins_len):
            found = True
        elif ins_matches_jcc_conditions(
            ins, addr, ins_len, prev_ins, prev_addr, prev_ins_len):
            found = True

        if found is True:
            rs.append(IntelJCCErratumResult(
                function_start_address=func.start,
                loop_start_address=None,
                jump_address=addr))

        prev_ins = ins
        prev_addr = addr
        prev_ins_len = ins_len

    return rs


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Error. Usage: {sys.argv[0]} /path/to/target")
        sys.exit(1)

    target_binary = sys.argv[1]

    intel_jcc_erratum_results = []
    with binaryninja.open_view(target_binary) as bv:
        for f in bv.functions:
            new_results = intel_jcc_erratum_analysis(f)
            if len(new_results):
                print(f)
                for nr in new_results:
                    print(f"\t{nr}")
            intel_jcc_erratum_results.extend(new_results)
