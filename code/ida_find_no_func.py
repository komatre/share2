import idc
import idautils
import idaapi

function_entry_points = [func_ea for func_ea in idautils.Functions()]

def first_search(baseaddr):
    #print("[!] Search Start : ", hex(idc.get_func_attr(baseaddr, idc.FUNCATTR_START)))
    is_no_func = True
    last_insn = ""
    for ea in idautils.FuncItems(baseaddr):
        # callが関数内に含まれている場合はスキップ
        if idc.print_insn_mnem(ea) in ["call"]:
            is_no_func = False
            break
        elif idc.print_insn_mnem(ea) in ["jmp"]:
            jmp_target = idc.get_operand_value(ea, 0)
            # jmp先のアドレスが関数の先頭アドレスか確認
            if jmp_target in function_entry_points:
                #print(f"Address {hex(jmp_target)} is a function.")
                is_no_func = False
                break
            else:
                #print(f"Address {hex(jmp_target)} is NOT a function.")
                pass
        last_insn = idc.print_insn_mnem(ea)   
    
    # 関数が閉じていない場合は, 処理対象から除外する
    if is_no_func:
        if last_insn not in ["ret", "retn"]:
            is_no_func = False
    
    # rename
    if is_no_func:
        old_name = idaapi.get_func_name(baseaddr)
        new_name = old_name.replace("sub", "no_func")
        idc.set_name(baseaddr, new_name)   

    print("[!] 1st search :", idaapi.get_func_name(baseaddr), hex(baseaddr), "=>", is_no_func)

def second_search(baseaddr):
    #print("[!] Search Start : ", hex(idc.get_func_attr(baseaddr, idc.FUNCATTR_START)))
    is_no_func = True
    last_insn = ""
    for ea in idautils.FuncItems(baseaddr):
        # callが関数内に含まれている場合　かつ　関数名がno_funcでない場合はスキップ
        if idc.print_insn_mnem(ea) in ["call"] and idc.print_operand(ea, 0) not in "no_func":
            #print("[DEBUG] ", idc.print_operand(ea, 0))
            is_no_func = False
            break
        elif idc.print_insn_mnem(ea) in ["jmp"]:
            jmp_target = idc.get_operand_value(ea, 0)
            # jmp先のアドレスが関数の先頭アドレスか確認
            if jmp_target in function_entry_points:
                #print(f"Address {hex(jmp_target)} is a function.")
                is_no_func = False
                break
            else:
                #print(f"Address {hex(jmp_target)} is NOT a function.")
                pass
        last_insn = idc.print_insn_mnem(ea)   
    
    # 関数が閉じていない場合は, 処理対象から除外する
    if is_no_func:
        if last_insn not in ["ret", "retn"]:
            is_no_func = False
    
    # rename
    # if is_no_func:
    #     old_name = idaapi.get_func_name(baseaddr)
    #     new_name = old_name.replace("sub", "no_func_wrap")
    #     idc.set_name(baseaddr, new_name)   

    print("[!] 2nd search :", idaapi.get_func_name(baseaddr), hex(baseaddr), "=>", is_no_func)

def debug():
    print("[+] ==============================")
    baseaddr = 0x020D927134
    is_no_func = True
    last_insn = ""
    for i, ea in enumerate(idautils.FuncItems(baseaddr)):
        print("[DEBUG] num=(", i, ") : ", hex(ea), "=>", idc.generate_disasm_line(ea, 0))
        if idc.print_insn_mnem(ea) in ["call"]:
            is_no_func = False
            break
        if idc.print_insn_mnem(ea) in ["jmp"]:
            jmp_target = idc.get_operand_value(ea, 0)
            if jmp_target in function_entry_points:
                print(f"Address {hex(jmp_target)} is a function.")
                is_no_func = False
                break
            else:
                print(f"Address {hex(jmp_target)} is NOT a function.")
        last_insn = idc.print_insn_mnem(ea)

    #.text:000000020D8D1380     sub_20D8D1380   proc near               ; CODE XREF: main+14B↓p
    #.text:000000020D8D1380 000                 jmp     short loc_20D8D139E
    #.text:000000020D8D1380     sub_20D8D1380   endp
    if is_no_func:
        if last_insn not in ["ret", "retn"]:
            is_no_func = False

    print("[!] Search Start :", idaapi.get_func_name(baseaddr), hex(baseaddr), "=>", is_no_func)
    print("[+] ==============================")

def main():
    print("[+] Start")
    # 1st search 
    # rename no_func
    for addr in idautils.Functions():
        func_name = idaapi.get_func_name(addr)
        if "sub_" in func_name:
            first_search(addr)
    
    # 2nd search
    # rename no_func_wrap
    for addr in idautils.Functions():
        func_name = idaapi.get_func_name(addr)
        if "sub_" in func_name:
            second_search(addr)

    print("[+] Fin")




main()
#debug()
