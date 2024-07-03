(provide 'readelf-capstone)

(require 'capstone-core)

(defun capstone-foreach-insn (f code start len addr count handle)
  ;; XXX[btv] -- assertions
  (let* ((disas (capstone--cs-disasm handle code start len addr count))
         )
    (when disas
      (readelf--foreach-insn f disas))))

;; XXX[btv] Do error handling in a better way than checking against a fixed list
;; Capstone error type
;; API version
(defconst capstone-CS_API_MAJOR 3)
(defconst capstone-CS_API_MINOR 0)

;; architectures
(defconst capstone-CS_ARCH_ARM 0)
(defconst capstone-CS_ARCH_ARM64 1)
(defconst capstone-CS_ARCH_MIPS 2)
(defconst capstone-CS_ARCH_X86 3)
(defconst capstone-CS_ARCH_PPC 4)
(defconst capstone-CS_ARCH_SPARC 5)
(defconst capstone-CS_ARCH_SYSZ 6)
(defconst capstone-CS_ARCH_XCORE 7)
(defconst capstone-CS_ARCH_MAX 8)
(defconst capstone-CS_ARCH_ALL #xFFFF)

;; disasm mode
(defconst capstone-CS_MODE_LITTLE_ENDIAN 0)            ; little-endian mode (default mode)
(defconst capstone-CS_MODE_ARM 0)                      ; ARM mode
(defconst capstone-CS_MODE_16 (lsh 1 1))               ; 16-bit mode (for X86)
(defconst capstone-CS_MODE_32 (lsh 1 2))               ; 32-bit mode (for X86)
(defconst capstone-CS_MODE_64 (lsh 1 3))               ; 64-bit mode (for X86, PPC)
(defconst capstone-CS_MODE_THUMB (lsh 1 4))            ; ARM's Thumb mode, including Thumb-2
(defconst capstone-CS_MODE_MCLASS (lsh 1 5))           ; ARM's Cortex-M series
(defconst capstone-CS_MODE_V8 (lsh 1 6))               ; ARMv8 A32 encodings for ARM
(defconst capstone-CS_MODE_MICRO (lsh 1 4))            ; MicroMips mode (MIPS architecture)
(defconst capstone-CS_MODE_MIPS3 (lsh 1 5))            ; Mips III ISA
(defconst capstone-CS_MODE_MIPS32R6 (lsh 1 6))         ; Mips32r6 ISA
(defconst capstone-CS_MODE_MIPSGP64 (lsh 1 7))         ; General Purpose Registers are 64-bit wide (MIPS arch)
(defconst capstone-CS_MODE_V9 (lsh 1 4))               ; Sparc V9 mode (for Sparc)
(defconst capstone-CS_MODE_BIG_ENDIAN (lsh 1 31))      ; big-endian mode
(defconst capstone-CS_MODE_MIPS32 capstone-CS_MODE_32) ; Mips32 ISA
(defconst capstone-CS_MODE_MIPS64 capstone-CS_MODE_64) ; Mips64 ISA

;; Capstone option type
(defconst capstone-CS_OPT_SYNTAX 1)         ; Intel X86 asm syntax (CS_ARCH_X86 arch)
(defconst capstone-CS_OPT_DETAIL 2)         ; Break down instruction structure into details
(defconst capstone-CS_OPT_MODE 3)           ; Change engine's mode at run-time
(defconst capstone-CS_OPT_MEM 4)            ; Change engine's mode at run-time
(defconst capstone-CS_OPT_SKIPDATA 5)       ; Skip data when disassembling
(defconst capstone-CS_OPT_SKIPDATA_SETUP 6) ; Setup user-defined function for SKIPDATA option

;; Capstone option value
(defconst capstone-CS_OPT_OFF 0) ; Turn OFF an option - default option of CS_OPT_DETAIL
(defconst capstone-CS_OPT_ON 3)  ; Turn ON an option (CS_OPT_DETAIL)

;; Common instruction operand types - to be consistent across all architectures.
(defconst capstone-CS_OP_INVALID 0)
(defconst capstone-CS_OP_REG 1)
(defconst capstone-CS_OP_IMM 2)
(defconst capstone-CS_OP_MEM 3)
(defconst capstone-CS_OP_FP 4)

;; Common instruction groups - to be consistent across all architectures.
(defconst capstone-CS_GRP_INVALID 0) ; uninitialized/invalid group.
(defconst capstone-CS_GRP_JUMP 1)    ; all jump instructions (conditional+direct+indirect jumps)
(defconst capstone-CS_GRP_CALL 2)    ; all call instructions
(defconst capstone-CS_GRP_RET 3)     ; all return instructions
(defconst capstone-CS_GRP_INT 4)     ; all interrupt instructions (int+syscall)
(defconst capstone-CS_GRP_IRET 5)    ; all interrupt return instructions

;; Capstone syntax value
(defconst capstone-CS_OPT_SYNTAX_DEFAULT   0) ; Default assembly syntax of all platforms (CS_OPT_SYNTAX)
(defconst capstone-CS_OPT_SYNTAX_INTEL     1) ; Intel X86 asm syntax - default syntax on X86 (CS_OPT_SYNTAX, CS_ARCH_X86)
(defconst capstone-CS_OPT_SYNTAX_ATT       2) ; ATT asm syntax (CS_OPT_SYNTAX, CS_ARCH_X86)
(defconst capstone-CS_OPT_SYNTAX_NOREGNAME 3) ; Asm syntax prints register name with only number - (CS_OPT_SYNTAX, CS_ARCH_PPC, CS_ARCH_ARM)

;; Capstone error type
(defconst capstone-CS_ERR_OK 0)         ; No error: everything was fine
(defconst capstone-CS_ERR_MEM 1)        ; Out-Of-Memory error: cs_open(), cs_disasm()
(defconst capstone-CS_ERR_ARCH 2)       ; Unsupported architecture: cs_open()
(defconst capstone-CS_ERR_HANDLE 3)     ; Invalid handle: cs_op_count(), cs_op_index()
(defconst capstone-CS_ERR_CSH 4)        ; Invalid csh argument: cs_close(), cs_errno(), cs_option()
(defconst capstone-CS_ERR_MODE 5)       ; Invalid/unsupported mode: cs_open()
(defconst capstone-CS_ERR_OPTION 6)     ; Invalid/unsupported option: cs_option()
(defconst capstone-CS_ERR_DETAIL 7)     ; Invalid/unsupported option: cs_option()
(defconst capstone-CS_ERR_MEMSETUP 8)
(defconst capstone-CS_ERR_VERSION 9)    ; Unsupported version (bindings)
(defconst capstone-CS_ERR_DIET 10)      ; Information irrelevant in diet engine
(defconst capstone-CS_ERR_SKIPDATA 11)  ; Access irrelevant data for "data" instruction in SKIPDATA mode
(defconst capstone-CS_ERR_X86_ATT 12)   ; X86 AT&T syntax is unsupported (opt-out at compile time)
(defconst capstone-CS_ERR_X86_INTEL 13) ; X86 Intel syntax is unsupported (opt-out at compile time)

;; query id for cs_support()
(defconst capstone-CS_SUPPORT_DIET (+ capstone-CS_ARCH_ALL 1))
(defconst capstone-CS_SUPPORT_X86_REDUCE (+ capstone-CS_ARCH_ALL 2))
;; capstone errors for testing against
(defconst capstone-errors `(,capstone-CS_ERR_OK
                            ,capstone-CS_ERR_MEM
                            ,capstone-CS_ERR_ARCH
                            ,capstone-CS_ERR_HANDLE
                            ,capstone-CS_ERR_CSH
                            ,capstone-CS_ERR_MODE
                            ,capstone-CS_ERR_OPTION
                            ,capstone-CS_ERR_DETAIL
                            ,capstone-CS_ERR_MEMSETUP
                            ,capstone-CS_ERR_VERSION
                            ,capstone-CS_ERR_DIET
                            ,capstone-CS_ERR_SKIPDATA
                            ,capstone-CS_ERR_X86_ATT
                            ,capstone-CS_ERR_X86_INTEL))

(defun capstone-open (arch mode)
  "Initiate a capstone instance for ARCH in MODE, returns handle value or nil"
  (cl-assert (integerp arch))
  (cl-assert (integerp mode))
  (let ((handle (capstone--cs-open arch mode)))
    (cond ((member handle capstone-errors)
           (message "capstone-open failed, error: %s" (capstone-strerror handle))
           nil)
          ;; passed all checks, we have a handle
          (t
           handle))))

;; capstone-CS_OPT_DETAIL is not handled in the backend, so turning it on is moot
(defun capstone-option (handle type value)
  "Set option of TYPE and VALUE for capstone instance HANDLE, returns t or nil"
  (cl-assert (integerp handle))
  (cl-assert (integerp type))
  (cl-assert (integerp value))
  (let ((ret (capstone--cs-option handle type value)))
    (if (= ret capstone-CS_ERR_OK)
        t
      (progn
        (message "capstone-option failed, error: %s" (capstone-strerror ret))
        nil))))
