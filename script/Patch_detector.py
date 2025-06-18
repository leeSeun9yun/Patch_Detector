import ida_bytes
import ida_funcs
import ida_kernwin
import ida_lines
import ida_name
import ida_segment
import ida_search
import ida_ua
import ida_ida
import ida_nalt
import idautils
import re
import idaapi

class SecurityPatchDetector:
    def __init__(self):
        self.security_patterns = {
            # Buffer overflow protection patterns
            'stack_guard': [
                "64 8B 0D ?? ?? 00 00",  # mov ecx, large fs:0 (stack canary)
                "64 48 8B 04 25 ?? ?? 00 00",  # mov rax, large fs:28h
            ],

            'buffer_checks': [
                "FF 15 ?? ?? ?? ??",  # call [__security_check_cookie]
                "E8 ?? ?? ?? ??",     # call __chkstk
                "FF 25 ?? ?? ?? ??",  # jmp [__security_check_cookie]
            ],
            
            # Input validation patterns
            'length_checks': [
                "3D ?? ?? ?? 00",  # cmp eax, large_value
                "81 F9 ?? ?? ?? ??",  # cmp ecx, large_value
                "83 F8 00",  # cmp eax, 0
                "85 C0",     # test eax, eax
                "85 C9",     # test ecx, ecx
            ],
            
            # Memory protection patterns
            'heap_protection': [
                "FF 15 ?? ?? ?? ??",  # call HeapValidate
                "E8 ?? ?? ?? ??",     # call RtlValidateHeap
                "FF 15 ?? ?? ?? ??",  # call HeapSetInformation
            ],
            
            # Integer overflow checks
            'overflow_checks': [
                "0F 80 ?? ?? ?? ??",  # jo (jump on overflow)
                "0F 81 ?? ?? ?? ??",  # jno (jump no overflow)
                "72 ??",        # jb (jump below - unsigned overflow)
                "73 ??",        # jae (jump above equal - no overflow)
                "77 ??",        # ja (jump above)
                "76 ??",        # jbe (jump below equal)
            ],
            
            # Format string protection
            'format_protection': [
                "FF 15 ?? ?? ?? ??",  # call _vsnprintf_s
                "E8 ?? ?? ?? ??",     # call sprintf_s
                "FF 15 ?? ?? ?? ??",  # call _snprintf_s
            ],
            
            # Control Flow Guard (CFG) patterns
            'cfg_protection': [
                "FF 15 ?? ?? ?? ??",  # call [_guard_check_icall_fptr]
                "48 8B 05 ?? ?? ?? ??",  # mov rax, [__guard_check_icall_fptr]
                "FF D0",        # call rax (indirect call guard)
            ],
            
            # Return Flow Guard (RFG) patterns
            'rfg_protection': [
                "E8 ?? ?? ?? ??",     # call _guard_retpoline_*
                "FF 15 ?? ?? ?? ??",  # call [_guard_*]
            ]
        }
        
        # Microsoft 예외 처리 함수들 (대소문자 구분 없이 검색)
        self.exception_functions = [
            'ExRaiseStatus', 'ExRaiseException', 'ExRaiseAccessViolation',
            'ExRaiseDatatypeMisalignment', 'RaiseException', 'RaiseStatus',
            'KiRaiseException', 'RtlRaiseException', 'RtlRaiseStatus',
            'NtRaiseException', 'ZwRaiseException', 'PsRaiseException',
            '_CxxThrowException', '__C_specific_handler', '__GSHandlerCheck',
            'RtlUnwind', 'RtlUnwindEx', 'RtlCaptureContext', 'RtlRestoreContext',
            'SetUnhandledExceptionFilter', 'UnhandledExceptionFilter',
            'KiUserExceptionDispatcher', 'RtlDispatchException'
        ]
        
        # SafeInt 및 정수 안전성 함수들
        self.safeint_functions = [
            # SafeInt 라이브러리 함수들
            'SafeIntOnOverflow', 'SafeIntException', 'SafeInt',
            'SafeIntNoOverflow', 'SafeIntOverflow', 'SafeIntDivideByZero',
            
            # Windows 정수 안전성 함수들 (intsafe.h)
            'UIntAdd', 'UIntSub', 'UIntMult', 'UIntToInt', 'IntToUInt',
            'ULongAdd', 'ULongSub', 'ULongMult', 'ULongToInt', 'IntToULong',
            'ULongLongAdd', 'ULongLongSub', 'ULongLongMult', 'ULongLongToInt',
            'SizeTAdd', 'SizeTSub', 'SizeTMult', 'SizeTToInt', 'IntToSizeT',
            'DWordAdd', 'DWordSub', 'DWordMult', 'DWordToInt', 'IntToDWord',
            
            # Windows 커널 정수 안전성 함수들 (ntintsafe.h)
            'RtlUIntAdd', 'RtlUIntSub', 'RtlUIntMult', 'RtlUIntToInt', 'RtlIntToUInt',
            'RtlULongAdd', 'RtlULongSub', 'RtlULongMult', 'RtlULongToInt', 'RtlIntToULong',
            'RtlULongLongAdd', 'RtlULongLongSub', 'RtlULongLongMult',
            'RtlSizeTAdd', 'RtlSizeTSub', 'RtlSizeTMult', 'RtlSizeTToInt',
            'RtlDWordAdd', 'RtlDWordSub', 'RtlDWordMult', 'RtlDWordToInt',
            
            # 추가 안전성 함수들
            'CheckedIntAdd', 'CheckedIntMult', 'CheckedIntSub',
            'SafeAllocMult', 'SafeAllocAdd', 'SafeStringCopy'
        ]

        # 보안 관련 API 카테고리
        self.security_apis = {
            'access_control': [
                'CheckTokenMembership', 'AccessCheck', 'AccessCheckByType',
                'PrivilegeCheck', 'ImpersonateLoggedOnUser', 'RevertToSelf',
                'OpenProcessToken', 'GetTokenInformation', 'SetTokenInformation'
            ],
            'crypto': [
                'CryptProtectData', 'CryptUnprotectData', 'CryptEncrypt', 'CryptDecrypt',
                'CryptCreateHash', 'CryptHashData', 'CryptSignHash', 'CryptVerifySignature',
                'BCryptEncrypt', 'BCryptDecrypt', 'BCryptCreateHash', 'BCryptHashData'
            ],
            'input_validation': [
                'IsValidCodePage', 'IsValidLocale', 'IsValidSid', 'IsValidAcl',
                'PathIsValidChar', 'UrlIsValidPath', 'ShlwApi validation functions'
            ]
        }

    def add_security_comment(self, addr, comment):
        """지정된 주소에 보안 관련 주석을 추가합니다."""
        try:
            existing_comment = ida_bytes.get_cmt(addr, 0)
            if existing_comment:
                if comment not in existing_comment:
                    new_comment = f"{existing_comment}\n{comment}"
                else:
                    return  # 중복 주석 방지
            else:
                new_comment = comment
                
            ida_bytes.set_cmt(addr, new_comment, 0)
            
            existing_rpt_comment = ida_bytes.get_cmt(addr, 1)
            if existing_rpt_comment:
                if comment not in existing_rpt_comment:
                    new_rpt_comment = f"{existing_rpt_comment}\n{comment}"
                else:
                    return
            else:
                new_rpt_comment = comment
            ida_bytes.set_cmt(addr, new_rpt_comment, 1)
            
            ida_lines.add_extra_line(addr, True, f"; {comment}")
            
        except Exception as e:
            print(f"Error adding comment at 0x{addr:X}: {str(e)}")

    def add_inline_comment(self, addr, comment):
        """인라인 주석을 추가합니다."""
        try:
            existing_eol = ida_bytes.get_cmt(addr, 0)
            if existing_eol:
                if comment not in existing_eol:
                    new_eol = f"{existing_eol} | {comment}"
                else:
                    return
            else:
                new_eol = comment
            
            ida_bytes.set_cmt(addr, new_eol, 0)
            ida_kernwin.refresh_idaview_anyway()
            
        except Exception as e:
            print(f"Error adding inline comment at 0x{addr:X}: {str(e)}")

    def add_pre_comment(self, addr, comment):
        """명령어 위에 주석을 추가합니다."""
        try:
            ida_lines.add_extra_line(addr, True, f"; {comment}")
            ida_lines.add_extra_line(addr, True, f"; {'='*50}")
            
        except Exception as e:
            print(f"Error adding pre-comment at 0x{addr:X}: {str(e)}")


    def is_security_relevant_instruction(self, insn, addr):
        """명령어가 실제로 보안과 관련있는지 판단합니다."""
        mnem = insn.get_canon_mnem()
        
        if mnem == 'test':
            return self.is_security_test_pattern(insn, addr)
        elif mnem == 'cmp':
            return self.is_security_cmp_pattern(insn, addr)
        elif mnem in ['jo', 'jno', 'jc', 'jnc', 'jb', 'jnb', 'ja', 'jae', 'jl', 'jle', 'jg', 'jge']:
            return self.is_security_jump_pattern(insn, addr)
        elif mnem == 'call':
            return self.is_security_call_pattern(insn, addr)
        
        return False

    def is_security_test_pattern(self, insn, addr):
        """test 명령어가 보안 검사인지 판단합니다."""
        if (insn.Op1.type == ida_ua.o_reg and 
            insn.Op2.type == ida_ua.o_reg and 
            insn.Op1.reg == insn.Op2.reg):
            
            next_addr = addr + insn.size
            next_insn = ida_ua.insn_t()
            if ida_ua.decode_insn(next_insn, next_addr):
                next_mnem = next_insn.get_canon_mnem()
                
                if next_mnem in ['jz', 'je', 'jnz', 'jne']:
                    jump_target = next_insn.Op1.addr
                    if self.is_error_handling_block(jump_target):
                        return True
                    
                    func = ida_funcs.get_func(addr)
                    if func and jump_target > (func.start_ea + (func.end_ea - func.start_ea) * 0.8):
                        return True
        
        elif (insn.Op1.type == ida_ua.o_reg and 
              insn.Op2.type == ida_ua.o_imm):
            security_masks = [0x80000000, 0x40000000, 0x1, 0x2, 0x4, 0x8, 0x10, 0x20]
            if insn.Op2.value in security_masks:
                return True
        
        return False

    def is_security_cmp_pattern(self, insn, addr):
        """cmp 명령어가 보안 검사인지 판단합니다."""
        security_bounds = [
            0, 1, 0x7FFFFFFF, 0xFFFFFFFF, 0x80000000,
            0x1000, 0x10000, 0x100000, 0x1000000,
            256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536
        ]

        if insn.Op2.type == ida_ua.o_imm:
            if insn.Op2.value in security_bounds:
                next_addr = addr + insn.size
                next_insn = ida_ua.insn_t()
                if ida_ua.decode_insn(next_insn, next_addr):
                    next_mnem = next_insn.get_canon_mnem()
                    if next_mnem in ['ja', 'jae', 'jb', 'jbe', 'jg', 'jge', 'jl', 'jle', 'jz', 'jnz']:
                        return True

        elif insn.Op2.type == ida_ua.o_reg:
            # 이전 명령어에서 imm를 mov 한 경우 추적
            prev_addr = ida_bytes.prev_head(addr, ida_ida.cvar.inf.min_ea) 
            prev_insn = ida_ua.insn_t()
            if ida_ua.decode_insn(prev_insn, prev_addr):
                if (prev_insn.get_canon_mnem() == 'mov' and
                    prev_insn.Op1.type == ida_ua.o_reg and
                    prev_insn.Op2.type == ida_ua.o_imm and
                    prev_insn.Op1.reg == insn.Op2.reg):
                    if prev_insn.Op2.value in security_bounds:
                        return True

        return False


    def is_security_jump_pattern(self, insn, addr):
        """조건부 점프가 보안 관련인지 판단합니다."""
        mnem = insn.get_canon_mnem()
        
        if mnem in ['jo', 'jno', 'jc', 'jnc']:
            prev_addr = ida_bytes.prev_head(addr, ida_ida.cvar.inf.min_ea)  
            if prev_addr != idaapi.BADADDR:
                prev_insn = ida_ua.insn_t()
                if ida_ua.decode_insn(prev_insn, prev_addr):
                    prev_mnem = prev_insn.get_canon_mnem()
                    if prev_mnem in ['add', 'sub', 'mul', 'imul', 'shl', 'shr', 'sal', 'sar']: # flag 설정 추정 연산 시
                        return True

        return False


    def is_security_call_pattern(self, insn, addr):
        """호출이 보안 관련인지 판단합니다."""
        if insn.Op1.type == ida_ua.o_mem:
            call_addr = insn.Op1.addr
            call_name = ida_name.get_name(call_addr)
            if call_name:
                # 예외 처리 함수 확인 (대소문자 구분 없이)
                if any(exc_func.lower() in call_name.lower() for exc_func in self.exception_functions):
                    return True
                # SafeInt 함수 확인 (대소문자 구분 없이)
                if any(safe_func.lower() in call_name.lower() for safe_func in self.safeint_functions):
                    return True
                # 보안 API 확인 (대소문자 구분 없이)
                for category, api_list in self.security_apis.items():
                    if any(api.lower() in call_name.lower() for api in api_list):
                        return True
        
        return False

    def is_error_handling_block(self, addr):
        """주소가 에러 처리 블록인지 판단합니다."""
        try:
            func_name = ida_funcs.get_func_name(addr)
            if func_name:
                error_keywords = ['error', 'fail', 'abort', 'exit', 'cleanup', 'exception', 'invalid', 'bad']
                if any(keyword in func_name.lower() for keyword in error_keywords):
                    return True
            
            block_end = addr + 30
            for head in idautils.Heads(addr, min(block_end, idaapi.BADADDR)):
                if ida_bytes.is_code(ida_bytes.get_flags(head)):
                    insn = ida_ua.insn_t()
                    if ida_ua.decode_insn(insn, head):
                        mnem = insn.get_canon_mnem()
                        
                        if mnem in ['ret', 'retn']:
                            return True
                        elif mnem == 'call':
                            if insn.Op1.type == ida_ua.o_mem:
                                call_name = ida_name.get_name(insn.Op1.addr)
                                if call_name:
                                    error_funcs = ['abort', 'exit', 'terminate', 'exception', 'raise', 'throw']
                                    if any(ef in call_name.lower() for ef in error_funcs):
                                        return True
        except:
            pass
        
        return False

    def classify_security_pattern(self, insn, addr):
        """보안 패턴의 구체적인 유형을 분류합니다."""
        mnem = insn.get_canon_mnem()
        
        if mnem == 'test':
            if (insn.Op1.type == ida_ua.o_reg and 
                insn.Op2.type == ida_ua.o_reg and 
                insn.Op1.reg == insn.Op2.reg):      # test eax, eax
                return "NULL pointer validation" 
            elif insn.Op2.type == ida_ua.o_imm:
                return "Security bit flag check"
        
        elif mnem == 'cmp':
            if insn.Op2.type == ida_ua.o_imm:
                value = insn.Op2.value
                if value == 0:
                    return "Zero/NULL comparison"
                elif value in [0x7FFFFFFF, 0xFFFFFFFF, 0x80000000]:
                    return "Integer overflow boundary check"
                elif value in [256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]:
                    return "Buffer size validation"
                else:
                    return "Security bounds checking"
        
        elif mnem in ['jo', 'jno']:
            return "Integer overflow protection"
        elif mnem in ['jc', 'jnc']:
            return "Carry flag overflow check"
        elif mnem in ['jb', 'jbe', 'ja', 'jae']:
            return "Unsigned bounds validation"
        elif mnem == 'call':
            if insn.Op1.type == ida_ua.o_mem:
                call_name = ida_name.get_name(insn.Op1.addr)
                if call_name:
                    # 예외 처리 함수 확인
                    for exc_func in self.exception_functions:
                        if exc_func.lower() in call_name.lower():
                            return f"Exception handling: {call_name}"
                    # SafeInt 함수 확인
                    for safe_func in self.safeint_functions:
                        if safe_func.lower() in call_name.lower():
                            return f"SafeInt protection: {call_name}"
        
        return "Security validation"

    def find_security_patterns(self):
        """보안 패턴을 찾고 주석을 추가합니다."""
        print("Searching for security patterns...")
        
        min_ea = ida_ida.cvar.inf.min_ea
        max_ea = ida_ida.cvar.inf.max_ea
        
        for pattern_type, patterns in self.security_patterns.items():
            print(f"Checking {pattern_type} patterns...")
            
            for pattern in patterns:
                try:
                    addr = ida_search.find_binary(min_ea, max_ea, pattern, 16, ida_search.SEARCH_DOWN)
                    
                    while addr != idaapi.BADADDR:
                        self.add_inline_comment(addr, f"SECURITY PATCH: {pattern_type}")
                        self.add_pre_comment(addr, f"Security Pattern Detected: {pattern_type}")
                        print(f"Found {pattern_type} at 0x{addr:X}")
                        
                        addr = ida_search.find_binary(addr + 1, max_ea, pattern, 16, ida_search.SEARCH_DOWN)
                        
                except Exception as e:
                    print(f"Error searching pattern {pattern}: {str(e)}")
                    continue

    def analyze_function_security(self):
        """함수별 보안 개선사항을 분석합니다."""
        print("Analyzing function-level security improvements...")
        
        for func_addr in idautils.Functions():
            try:
                func = ida_funcs.get_func(func_addr)
                if not func:
                    continue
                    
                func_name = ida_name.get_name(func_addr)
                if not func_name:
                    continue
                    
                # 함수 내부의 보안 패턴 검사
                self.analyze_function_internals(func)
                
            except Exception as e:
                print(f"Error analyzing function at 0x{func_addr:X}: {str(e)}")
                continue

    def analyze_function_internals(self, func):
        """함수 내부의 보안 관련 코드를 분석합니다."""
        has_bounds_check = False
        has_null_check = False
        has_overflow_check = False
        has_exception_handling = False
        has_safeint_usage = False
        
        try:
            for head in idautils.Heads(func.start_ea, func.end_ea):
                if ida_bytes.is_code(ida_bytes.get_flags(head)):
                    insn = ida_ua.insn_t()
                    if ida_ua.decode_insn(insn, head):
                        if self.is_security_relevant_instruction(insn, head):
                            security_type = self.classify_security_pattern(insn, head)
                            if security_type:
                                self.add_inline_comment(head, f"SECURITY: {security_type}")
                                
                                # 보안 기능 추적
                                if "NULL pointer" in security_type:
                                    has_null_check = True
                                elif "bounds" in security_type.lower() or "validation" in security_type.lower():
                                    has_bounds_check = True
                                elif "overflow" in security_type.lower():
                                    has_overflow_check = True
                                elif "Exception handling" in security_type:
                                    has_exception_handling = True
                                elif "SafeInt" in security_type:
                                    has_safeint_usage = True
            
            # 함수 레벨 보안 개선사항 주석
            security_features = []
            if has_null_check:
                security_features.append("NULL pointer validation")
            if has_bounds_check:
                security_features.append("bounds checking")
            if has_overflow_check:
                security_features.append("overflow protection")
            if has_exception_handling:
                security_features.append("exception handling")
            if has_safeint_usage:
                security_features.append("SafeInt protection")
                
            if security_features:
                comment = f"SECURITY IMPROVEMENTS: {', '.join(security_features)}"
                self.add_security_comment(func.start_ea, comment)
                
        except Exception as e:
            print(f"Error analyzing function internals: {str(e)}")

    def find_exception_handling_functions(self):
        """예외 처리 함수들을 찾고 주석을 추가합니다."""
        print("Analyzing exception handling functions...")
        
        try:
            # Import 테이블에서 함수 찾기
            import_count = ida_nalt.get_import_module_qty()
            
            for i in range(import_count):
                def enum_import_names(ea, name, ordinal):
                    if name is not None:
                        try:
                            # 예외 처리 함수 확인 (대소문자 구분 없이)
                            for exc_func in self.exception_functions:
                                if exc_func.lower() in name.lower():
                                    self.add_inline_comment(ea, f"SECURITY: Exception handling - {name}")
                                    self.add_pre_comment(ea, f"Microsoft Exception Function: {name}")
                                    print(f"Found exception handling function: {name} at 0x{ea:X}")
                                    break
                                    
                        except Exception as e:
                            print(f"Error processing exception function {name}: {str(e)}")
                    return True
                
                ida_nalt.enum_import_names(i, enum_import_names)
            
            # 코드 영역에서 함수 호출 패턴 찾기
            for func_addr in idautils.Functions():
                func = ida_funcs.get_func(func_addr)
                if func:
                    for head in idautils.Heads(func.start_ea, func.end_ea):
                        if ida_bytes.is_code(ida_bytes.get_flags(head)):
                            insn = ida_ua.insn_t()
                            if ida_ua.decode_insn(insn, head):
                                if insn.get_canon_mnem() == 'call':
                                    if insn.Op1.type == ida_ua.o_mem:
                                        call_name = ida_name.get_name(insn.Op1.addr)
                                        if call_name is not None:
                                            for exc_func in self.exception_functions:
                                                if exc_func.lower() in call_name.lower():
                                                    self.add_inline_comment(head, f"SECURITY: Exception handling - {call_name}")
                                                    print(f"Found exception handling call: {call_name} at 0x{head:X}")
                                                    break
                
        except Exception as e:
            print(f"Error analyzing exception handling functions: {str(e)}")

    def find_safeint_functions(self):
        """SafeInt 관련 함수들을 찾고 주석을 추가합니다."""
        print("Analyzing SafeInt protection functions...")
        
        try:
            # Import 테이블에서 함수 찾기
            import_count = ida_nalt.get_import_module_qty()
            
            for i in range(import_count):
                def enum_import_names(ea, name, ordinal):
                    if name is not None:
                        try:
                            # SafeInt 함수 확인 (대소문자 구분 없이)
                            for safe_func in self.safeint_functions:
                                if safe_func.lower() in name.lower():
                                    self.add_inline_comment(ea, f"SECURITY: SafeInt protection - {name}")
                                    self.add_pre_comment(ea, f"SafeInt/Integer Safety Function: {name}")
                                    print(f"Found SafeInt function: {name} at 0x{ea:X}")
                                    break
                                    
                        except Exception as e:
                            print(f"Error processing SafeInt function {name}: {str(e)}")
                    return True
                
                ida_nalt.enum_import_names(i, enum_import_names)
            
            # 코드 영역에서 SafeInt 함수 호출 패턴 찾기
            for func_addr in idautils.Functions():
                func = ida_funcs.get_func(func_addr)
                if func:
                    for head in idautils.Heads(func.start_ea, func.end_ea):
                        if ida_bytes.is_code(ida_bytes.get_flags(head)):
                            insn = ida_ua.insn_t()
                            if ida_ua.decode_insn(insn, head):
                                if insn.get_canon_mnem() == 'call':
                                    if insn.Op1.type == ida_ua.o_mem:
                                        call_name = ida_name.get_name(insn.Op1.addr)
                                        if call_name is not None:
                                            for safe_func in self.safeint_functions:
                                                if safe_func.lower() in call_name.lower():
                                                    self.add_inline_comment(head, f"SECURITY: SafeInt protection - {call_name}")
                                                    print(f"Found SafeInt call: {call_name} at 0x{head:X}")
                                                    break
                
        except Exception as e:
            print(f"Error analyzing SafeInt functions: {str(e)}")

    def find_specific_exception_functions(self):
        """xRaiseStatus와 같은 특정 예외 처리 함수를 찾습니다."""
        print("Searching for specific exception handling functions...")
        
        # 추가 예외 처리 함수들 (x prefix 포함)
        additional_exception_functions = [
            'xRaiseStatus', 'xRaiseException', 'xRaiseAccessViolation',
            'xExRaiseStatus', 'xExRaiseException', 'xKiRaiseException',
            'xNtRaiseException', 'xZwRaiseException', 'xRtlRaiseException',
            'xRtlRaiseStatus', 'xPsRaiseException'
        ]
        
        # 기존 예외 함수 리스트와 병합
        all_exception_functions = self.exception_functions + additional_exception_functions
        
        try:
            # 모든 함수명에서 검색
            for func_addr in idautils.Functions():
                func_name = ida_name.get_name(func_addr)
                if func_name is not None:
                    for exc_func in all_exception_functions:
                        if exc_func.lower() in func_name.lower():
                            self.add_inline_comment(func_addr, f"SECURITY: Exception handling - {func_name}")
                            self.add_pre_comment(func_addr, f"Exception Function Detected: {func_name}")
                            print(f"Found exception function: {func_name} at 0x{func_addr:X}")
                            break
            
            # 문자열 검색으로도 찾기
            for exc_func in all_exception_functions:
                try:
                    # 바이너리에서 문자열로 검색
                    search_str = exc_func.encode('ascii')
                    addr = ida_search.find_binary(ida_ida.cvar.inf.min_ea, ida_ida.cvar.inf.max_ea, 
                                                search_str.hex(), 16, ida_search.SEARCH_DOWN)
                    
                    while addr != idaapi.BADADDR:
                        self.add_inline_comment(addr, f"SECURITY: Exception string reference - {exc_func}")
                        print(f"Found exception string reference: {exc_func} at 0x{addr:X}")
                        
                        addr = ida_search.find_binary(addr + 1, ida_ida.cvar.inf.max_ea, 
                                                    search_str.hex(), 16, ida_search.SEARCH_DOWN)
                except Exception as e:
                    print(f"Error searching for {exc_func}: {str(e)}")
                    continue
                
        except Exception as e:
            print(f"Error in specific exception function search: {str(e)}")

    def find_safeint_overflow_functions(self):
        """SafeIntOnOverflow와 관련 함수들을 특별히 처리합니다."""
        print("Searching for SafeIntOnOverflow and related functions...")
        
        # SafeIntOnOverflow 특화 함수들
        safeint_overflow_functions = [
            'SafeIntOnOverflow', 'SafeIntOnUnderflow', 'SafeIntOnDivideByZero',
            'SafeIntOverflowHandler', 'SafeIntException', 'SafeIntError',
            'OnSafeIntOverflow', 'OnSafeIntUnderflow', 'HandleSafeIntOverflow'
        ]
        
        try:
            # 함수명에서 검색
            for func_addr in idautils.Functions():
                func_name = ida_name.get_name(func_addr)
                if func_name is not None:
                    for safe_overflow in safeint_overflow_functions:
                        if safe_overflow.lower() in func_name.lower():
                            self.add_inline_comment(func_addr, f"SECURITY: SafeInt overflow protection - {func_name}")
                            self.add_pre_comment(func_addr, f"SafeInt Overflow Handler: {func_name}")
                            print(f"Found SafeInt overflow function: {func_name} at 0x{func_addr:X}")
                            break
            
            # Import 테이블에서 검색
            import_count = ida_nalt.get_import_module_qty()
            
            for i in range(import_count):
                def enum_safeint_imports(ea, name, ordinal):
                    if name is not None:
                        try:
                            for safe_overflow in safeint_overflow_functions:
                                if safe_overflow.lower() in name.lower():
                                    self.add_inline_comment(ea, f"SECURITY: SafeInt overflow import - {name}")
                                    self.add_pre_comment(ea, f"SafeInt Overflow Import: {name}")
                                    print(f"Found SafeInt overflow import: {name} at 0x{ea:X}")
                                    break
                        except Exception as e:
                            print(f"Error processing SafeInt overflow import {name}: {str(e)}")
                    return True
                
                ida_nalt.enum_import_names(i, enum_safeint_imports)
            
            # 문자열 참조로도 검색
            for safe_overflow in safeint_overflow_functions:
                try:
                    search_str = safe_overflow.encode('ascii')
                    addr = ida_search.find_binary(ida_ida.cvar.inf.min_ea, ida_ida.cvar.inf.max_ea, 
                                                search_str.hex(), 16, ida_search.SEARCH_DOWN)
                    
                    while addr != idaapi.BADADDR:
                        self.add_inline_comment(addr, f"SECURITY: SafeInt overflow reference - {safe_overflow}")
                        print(f"Found SafeInt overflow reference: {safe_overflow} at 0x{addr:X}")
                        
                        addr = ida_search.find_binary(addr + 1, ida_ida.cvar.inf.max_ea, 
                                                    search_str.hex(), 16, ida_search.SEARCH_DOWN)
                except Exception as e:
                    print(f"Error searching SafeInt overflow function {safe_overflow}: {str(e)}")
                    continue
                
        except Exception as e:
            print(f"Error in SafeInt overflow function search: {str(e)}")

    def analyze_security_api_usage(self):
        """보안 API 사용을 분석합니다."""
        print("Analyzing security API usage...")
        
        try:
            for category, api_list in self.security_apis.items():
                print(f"Checking {category} APIs...")
                
                for api in api_list:
                    # 함수명에서 검색
                    for func_addr in idautils.Functions():
                        func_name = ida_name.get_name(func_addr)
                        if func_name is not None and api.lower() in func_name.lower():
                            self.add_inline_comment(func_addr, f"SECURITY API: {category} - {func_name}")
                            self.add_pre_comment(func_addr, f"Security API ({category}): {func_name}")
                            print(f"Found {category} API: {func_name} at 0x{func_addr:X}")
                    
                    # Import에서 검색
                    import_count = ida_nalt.get_import_module_qty()
                    
                    for i in range(import_count):
                        def enum_security_api_imports(ea, name, ordinal):
                            if name is not None and api.lower() in name.lower():
                                try:
                                    self.add_inline_comment(ea, f"SECURITY API: {category} - {name}")
                                    self.add_pre_comment(ea, f"Security API Import ({category}): {name}")
                                    print(f"Found {category} API import: {name} at 0x{ea:X}")
                                except Exception as e:
                                    print(f"Error processing security API {name}: {str(e)}")
                            return True
                        
                        ida_nalt.enum_import_names(i, enum_security_api_imports)
                
        except Exception as e:
            print(f"Error analyzing security API usage: {str(e)}")

    def generate_security_report(self):
        """보안 패치 분석 보고서를 생성합니다."""
        print("Generating security patch analysis report...")
        
        report = []
        report.append("=" * 80)
        report.append("SECURITY PATCH ANALYSIS REPORT")
        report.append("=" * 80)
        report.append("")

        # 통계 수집
        security_comments = 0
        exception_functions = 0
        safeint_functions = 0
        security_apis = 0
        
        try:
            for func_addr in idautils.Functions():
                func_name = ida_name.get_name(func_addr)
                if func_name is not None:
                    for exc_func in self.exception_functions:
                        if exc_func.lower() in func_name.lower():
                            exception_functions += 1
                            break
                    for safe_func in self.safeint_functions:
                        if safe_func.lower() in func_name.lower():
                            safeint_functions += 1
                            break
                    for category, api_list in self.security_apis.items():
                        if any(api.lower() in func_name.lower() for api in api_list):
                            security_apis += 1
                            break
            
            report.append(f"Total Exception Handling Functions Found: {exception_functions}")
            report.append(f"Total SafeInt Protection Functions Found: {safeint_functions}")
            report.append(f"Total Security API Functions Found: {security_apis}")
            report.append("")
            report.append("SECURITY IMPROVEMENTS DETECTED:")
            report.append("-" * 40)
            if exception_functions > 0:
                report.append("✓ Exception Handling Implementation")
            if safeint_functions > 0:
                report.append("✓ SafeInt Integer Overflow Protection")
            if security_apis > 0:
                report.append("✓ Security API Usage")
            report.append("")
            report.append("ANALYSIS COMPLETED: " + str(ida_kernwin.get_kernel_version()))
            
            # 보고서 출력
            report_text = "\n".join(report)
            print(report_text)
            
            # IDA 뷰에 주석 추가
            main_func = ida_ida.cvar.inf.start_ea
            self.add_pre_comment(main_func, "SECURITY PATCH ANALYSIS REPORT")
            for line in report:
                if line.strip():
                    self.add_pre_comment(main_func, line)

            # 텍스트 파일로 저장
            output_path = ida_nalt.get_input_file_path() + "_security_report.txt"
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(report_text)
            print(f"Report written to: {output_path}")

        except Exception as e:
            print(f"Error generating security report: {str(e)}")


    def run_analysis(self):
        """전체 보안 패치 분석을 실행합니다."""
        print("Starting Security Patch Detection Analysis...")
        print("=" * 60)
        
        try:
            # 기본 보안 패턴 검색
            self.find_security_patterns()
            
            # 함수별 보안 분석
            self.analyze_function_security()
            
            # 예외 처리 함수 분석 (xRaiseStatus 포함)
            self.find_exception_handling_functions()
            self.find_specific_exception_functions()
            
            # SafeInt 함수 분석 (SafeIntOnOverflow 포함)
            self.find_safeint_functions()
            self.find_safeint_overflow_functions()
            
            # 보안 API 사용 분석
            self.analyze_security_api_usage()
            
            # 분석 보고서 생성
            self.generate_security_report()
            
            print("=" * 60)
            print("Security Patch Detection Analysis Completed!")
            print("Check the comments in IDA for detailed security annotations.")
            
            # IDA 뷰 새로고침
            ida_kernwin.refresh_idaview_anyway()
            
        except Exception as e:
            print(f"Error during analysis: {str(e)}")
            import traceback
            traceback.print_exc()

def main():
    """메인 실행 함수"""
    try:
        detector = SecurityPatchDetector()
        detector.run_analysis()
    except Exception as e:
        print(f"Fatal error: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()