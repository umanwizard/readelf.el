(provide 'readelf)

(require 'bindat)
(require 'dash)

(require 'readelf-disasm)

(defconst readelf-magic #x7f454c46)
(defconst readelf-elfclass64 2)
(defconst readelf-elfdata2lsb 1)
(defconst readelf-ev-current 1)

(defconst readelf-le64-header-bindat-spec
  (bindat-type
    (magic uint 32)
    (class u8)
    (data u8)
    (identversion u8)
    (osabi u8)
    (abiversion u8)
    (_ fill 7)
    (type uint 16 t)
    (machine uint 16 t)
    (version uint 32 t)
    (entry uint 64 t)
    (phoff uint 64 t)
    (shoff uint 64 t)
    (flags uint 32 t)
    (ehsize uint 16 t)
    (phentsize uint 16 t)
    (phnum uint 16 t)
    (shentsize uint 16 t)
    (shnum uint 16 t)
    (shstrndx uint 16 t)))

(defconst readelf-le64-phdr-bindat-spec
  (bindat-type
    (type uint 32 t)
    (flags uint 32 t)
    (offset uint 64 t)
    (vaddr uint 64 t)
    (paddr uint 64 t)
    (filesz uint 64 t)
    (memsz uint 64 t)
    (align uint 64 t)))

(defconst readelf-le64-shdr-bindat-spec
  (bindat-type
    (name uint 32 t)
    (type uint 32 t)
    (flags uint 64 t)
    (addr uint 64 t)
    (offset uint 64 t)
    (size uint 64 t)
    (link uint 32 t)
    (info uint 32 t)
    (addralign uint 64 t)
    (entsize uint 64 t)))

(defconst readelf-le-nhdr-bindat-spec
  (bindat-type
    (namesz uint 32 t)
    (descsz uint 32 t)
    (type uint 32 t)))

(defconst readelf-le64-sym-bindat-spec
  (bindat-type
    (name uint 32 t)
    (info uint 8 t)
    (other uint 8 t)
    (shndx uint 16 t)
    (value uint 64 t)
    (size uint 64 t)))

;; like `with-current-buffer', but
;; inhibits read only
(defmacro readelf--wcb (buffer-or-name &rest body)
  (declare (indent 1) (debug t))
  `(with-current-buffer
       ,buffer-or-name
     (let ((inhibit-read-only t))
       ,@body)))

(defun readelf-get-header ()
    (let ((header-bytes (buffer-substring-no-properties 1 65)))
      (bindat-unpack readelf-le64-header-bindat-spec header-bytes)))

(defun readelf-validate-header (h)
  (unless (= (cdr (assq 'magic h)) readelf-magic)
    (error "bad elf magic"))
  (unless (= (cdr (assq 'class h)) readelf-elfclass64)
    (error "only 64-bit elf files supported"))
  (unless (= (cdr (assq 'data h)) readelf-elfdata2lsb)
    (error "only LE elf files supported"))
  (unless (= (cdr (assq 'identversion h)) readelf-ev-current)
    (error "bad elf ident version"))
  (unless (= (cdr (assq 'ehsize h)) 64)
    (error "bad elf header size"))
  (unless (>= (cdr (assq 'phentsize h)) 56)
    (error "bad ph entry size"))
  (unless (>= (cdr (assq 'shentsize h)) 64)
    (error "bad sh entry size"))
  h)

(defmacro readelf--mkenum (enum-name &rest names-and-values)
  `(progn ,@(mapcar
             (lambda (nv)
               (let* ((name (symbol-name (car nv)))
                      (val (cadr nv))
                      (sym (intern (concat "readelf--" (symbol-name enum-name) "/" name))))
                 `(defconst ,sym ,val)))
             names-and-values)
          (defun ,(intern (concat "readelf--" (symbol-name enum-name) "-name"))
               (val)
             (pcase val
               ,@(mapcar
                  (lambda (nv)
                    (let* ((name (symbol-name (car nv)))
                           (val (cadr nv)))
                      `(,val ,name)))
                  names-and-values)))))

(readelf--mkenum symviz
                 (STV_DEFAULT 0)
                 (STV_INTERNAL 1)
                 (STV_HIDDEN 2)
                 (STV_PROTECTED 3))

(readelf--mkenum symtype
                 (STT_NOTYPE 0)
                 (STT_OBJECT 1)
                 (STT_FUNC 2)
                 (STT_SECTION 3)
                 (STT_FILE 4)
                 (STT_FILE 5)
                 (STT_TLS 6)
                 (STT_NUM 7)
                 (STT_LOOS 10)
                 (STT_GNU_IFUNC 10)
                 (STT_HIOS 12)
                 (STT_LOPROC 13)
                 (STT_HIPROC 15))

(readelf--mkenum e_type
                 (ET_NONE 0)
                 (ET_REL 1)
                 (ET_EXEC 2)
                 (ET_DYN 3)
                 (ET_CORE 4)
                 (ET_NUM 5)
                 (ET_LOOS #xfe00)
                 (ET_HIOS #xfeff)
                 (ET_LOPROC #xff00)
                 (ET_HIPROC #xffff))

(readelf--mkenum p_type
                 (PT_NULL 0)
                 (PT_LOAD 1)
                 (PT_DYNAMIC 2)
                 (PT_INTERP 3)
                 (PT_NOTE 4)
                 (PT_SHLIB 5)
                 (PT_PHDR 6)
                 (PT_TLS 7)
                 (PT_NUM 8)
                 (PT_LOOS #x60000000)
                 (PT_GNU_EH_FRAME #x6474e550)
                 (PT_GNU_STACK #x6474e551)
                 (PT_GNU_RELRO #x6474e552)
                 (PT_GNU_PROPERTY #x6474e553)
                 (PT_GNU_SFRAME #x6474e554)
                 (PT_LOSUNW #x6ffffffa)
                 (PT_SUNWBSS #x6ffffffa)
                 (PT_SUNWSTACK #x6ffffffb)
                 (PT_HISUNW #x6fffffff)
                 (PT_HIOS #x6fffffff)
                 (PT_LOPROC #x70000000)
                 (PT_HIPROC #x7fffffff))

(readelf--mkenum sh_type
                 (SHT_NULL 0)
                 (SHT_PROGBITS 1)
                 (SHT_SYMTAB 2)
                 (SHT_STRTAB 3)
                 (SHT_RELA 4)
                 (SHT_HASH 5)
                 (SHT_DYNAMIC 6)
                 (SHT_NOTE 7)
                 (SHT_NOBITS 8)
                 (SHT_REL 9)
                 (SHT_SHLIB 10)
                 (SHT_DYNSYM 11)
                 (SHT_INIT_ARRAY 14)
                 (SHT_FINI_ARRAY 15)
                 (SHT_PREINIT_ARRAY 16)
                 (SHT_GROUP 17)
                 (SHT_SYMTAB_SHNDX 18)
                 (SHT_RELR 19)
                 (SHT_NUM 20)
                 (SHT_LOOS #x60000000)
                 (SHT_GNU_ATTRIBUTES #x6ffffff5)
                 (SHT_GNU_HASH #x6ffffff6)
                 (SHT_GNU_LIBLIST #x6ffffff7)
                 (SHT_CHECKSUM #x6ffffff8)
                 (SHT_LOSUNW #x6ffffffa)
                 (SHT_SUNW_move #x6ffffffa)
                 (SHT_SUNW_COMDAT #x6ffffffb)
                 (SHT_SUNW_syminfo #x6ffffffc)
                 (SHT_GNU_verdef #x6ffffffd)
                 (SHT_GNU_verneed #x6ffffffe)
                 (SHT_GNU_versym #x6fffffff)
                 (SHT_HISUNW #x6fffffff)
                 (SHT_HIOS #x6fffffff)
                 (SHT_LOPROC #x70000000)
                 (SHT_HIPROC #x7fffffff)
                 (SHT_LOUSER #x80000000)
                 (SHT_HIUSER #x8fffffff))

(readelf--mkenum gnu_note_type
                 (NT_GNU_ABI_TAG 1)
                 (NT_GNU_HWCAP 2)
                 (NT_GNU_BUILD_ID 3)
                 (NT_GNU_GOLD_VERSION 4)
                 (NT_GNU_PROPERTY_TYPE_0 5))

(readelf--mkenum core_note_type
                 (NT_PRSTATUS 1)
                 (NT_PRFPREG 2)
                 (NT_FPREGSET 2)
                 (NT_PRPSINFO 3)
                 (NT_PRXREG 4)
                 (NT_TASKSTRUCT 4)
                 (NT_PLATFORM 5)
                 (NT_AUXV 6)
                 (NT_GWINDOWS 7)
                 (NT_ASRS 8)
                 (NT_PSTATUS 10)
                 (NT_PSINFO 13)
                 (NT_PRCRED 14)
                 (NT_UTSNAME 15)
                 (NT_LWPSTATUS 16)
                 (NT_LWPSINFO 17)
                 (NT_PRFPXREG 20)
                 (NT_SIGINFO #x53494749)
                 (NT_FILE #x46494c45)
                 (NT_PRXFPREG #x46e62b7f)
                 (NT_PPC_VMX #x100)
                 (NT_PPC_SPE #x101)
                 (NT_PPC_VSX #x102)
                 (NT_PPC_TAR #x103)
                 (NT_PPC_PPR #x104)
                 (NT_PPC_DSCR #x105)
                 (NT_PPC_EBB #x106)
                 (NT_PPC_PMU #x107)
                 (NT_PPC_TM_CGPR #x108)
                 (NT_PPC_TM_CFPR #x109)
                 (NT_PPC_TM_CVMX #x10a)
                 (NT_PPC_TM_CVSX #x10b)
                 (NT_PPC_TM_SPR #x10c)
                 (NT_PPC_TM_CTAR #x10d)
                 (NT_PPC_TM_CPPR #x10e)
                 (NT_PPC_TM_CDSCR #x10f)
                 (NT_PPC_PKEY #x110)
                 (NT_386_TLS #x200)
                 (NT_386_IOPERM #x201)
                 (NT_X86_XSTATE #x202)
                 (NT_S390_HIGH_GPRS #x300)
                 (NT_S390_TIMER #x301)
                 (NT_S390_TODCMP #x302)
                 (NT_S390_TODPREG #x303)
                 (NT_S390_CTRS #x304)
                 (NT_S390_PREFIX #x305)
                 (NT_S390_LAST_BREAK #x306)
                 (NT_S390_SYSTEM_CALL #x307)
                 (NT_S390_TDB #x308)
                 (NT_S390_VXRS_LOW #x309)
                 (NT_S390_VXRS_HIGH #x30a)
                 (NT_S390_GS_CB #x30b)
                 (NT_S390_GS_BC #x30c)
                 (NT_S390_RI_CB #x30d)
                 (NT_S390_PV_CPU_DATA #x30e)
                 (NT_ARM_VFP #x400)
                 (NT_ARM_TLS #x401)
                 (NT_ARM_HW_BREAK #x402)
                 (NT_ARM_HW_WATCH #x403)
                 (NT_ARM_SYSTEM_CALL #x404)
                 (NT_ARM_SVE #x405)
                 (NT_ARM_PAC_MASK #x406)
                 (NT_ARM_PACA_KEYS #x407)
                 (NT_ARM_PACG_KEYS #x408)
                 (NT_ARM_TAGGED_ADDR_CTRL #x409)
                 (NT_ARM_PAC_ENABLED_KEYS #x40a)
                 (NT_VMCOREDD #x700)
                 (NT_MIPS_DSP #x800)
                 (NT_MIPS_FP_MODE #x801)
                 (NT_MIPS_MSA #x802)
                 (NT_LOONGARCH_CPUCFG #xa00)
                 (NT_LOONGARCH_CSR #xa01)
                 (NT_LOONGARCH_LSX #xa02)
                 (NT_LOONGARCH_LASX #xa03)
                 (NT_LOONGARCH_LBT #xa04))

(defun readelf--read-pt-note (phdr)
  (let ((cur (alist-get 'offset phdr))
        (rem (alist-get 'filesz phdr))
        rnotes)
    (while (>= rem 12)
      (let* ((s (with-current-buffer readelf-fbuf
                  (buffer-substring-no-properties (+ cur 1) (+ cur 13))))
             (nhdr (bindat-unpack readelf-le-nhdr-bindat-spec s))
             (namesz (alist-get 'namesz nhdr))
             (descsz (alist-get 'descsz nhdr))
             (type (alist-get 'type nhdr))
             name desc)
        (setq
         cur (+ cur 12)
         rem (- rem 12))
        (unless (>= rem namesz) (error "bad note"))
        (setq
         name (with-current-buffer readelf-fbuf
                (readelf--cstr (1+ cur) (1- namesz))))
        (unless (= (length name) (1- namesz)) (error "bad note"))
        (setq
         cur (+ cur namesz)
         rem (- rem namesz))
        (unless (>= rem descsz) (error "bad note"))
        (setq
         desc (with-current-buffer readelf-fbuf
                (buffer-substring-no-properties (+ cur 1) (+ cur 1 descsz))))        
        (setq
         cur (+ cur descsz)
         rem (- rem descsz))
        (setq
         rnotes (cons `(,name ,desc . ,type) rnotes))))
    (nreverse rnotes)))

;; Reads the symbol string tab beginning
;; at `idx' (1-indexed)
(defun readelf--read-strtab-at (offset)
  (let* ((sz (alist-get 'size readelf-strtab))
         (max (1+ (- sz offset)))
         (off (+ offset (alist-get 'offset readelf-strtab))))
    (with-current-buffer readelf-fbuf (readelf--cstr off max))))

(defun readelf--read-symtab (shdr)
  (let ((cur (alist-get 'offset shdr))
        (rem (alist-get 'size shdr))
        (n 0)
        rsyms)
    (while (>= rem 24)
      (let* ((s (with-current-buffer readelf-fbuf
                  (buffer-substring-no-properties (+ cur 1) (+ cur 25))))
             (sym (bindat-unpack readelf-le64-sym-bindat-spec s))
             (nameidx (alist-get 'name sym))
             (name (readelf--read-strtab-at (1+ nameidx))))        
        (setq cur (+ cur 24))
        (setq rem (- rem 24))
        (setq n (1+ n))
        (when (= (% n 1000) 0)
          (message (format "%d" n)))
        (unless
            (or
             (equal name "")
             ;; [btv] IDK if this is the right way to filter symbols.
             ;; Check what nm does.
             (= (alist-get 'value sym) 0)
             (eq (alist-get 'other sym) readelf--symviz/STV_INTERNAL)
             (eq (alist-get 'info sym) readelf--symtype/STT_NOTYPE))
          (setf (alist-get 'name sym) name)
          (setq rsyms `(,sym . ,rsyms)))))
    (setq-local readelf-symarray
                (sort (vconcat readelf-symarray
                               (mapcar (lambda (sym)
                                         (cons
                                          (alist-get 'value sym)
                                          (alist-get 'name sym)))
                                       rsyms))
                      (lambda (a b)
                        (< (car a) (car b)))))
    (nreverse rsyms)))

(defun readelf--hex (bytes)
  (apply #'concat
         (mapcar
          (lambda (b)
            (format "%x" b))
          bytes)))

(defun readelf--expand-pt-note (phdr)
  (unless (alist-get :notes phdr)
    (setf (alist-get :notes phdr) (readelf--read-pt-note phdr)))
  (goto-char (cdr (alist-get :header phdr)))
  (dolist (note (alist-get :notes phdr))
    (let* ((name (car note))
           (desc (cadr note))
           (type (cddr note))
           (type-str
            (cond
             ((= (alist-get 'type readelf-header) readelf--e_type/ET_CORE)
              (readelf--core_note_type-name type))
             ((equal name "GNU") (readelf--gnu_note_type-name type))))
           (inhibit-read-only t))
      (insert "Note " name " of type " type-str ": " (readelf--hex desc) "\n"))))

(defun readelf--expand-symtab (shdr)
  (unless (alist-get :syms shdr)
    (setf (alist-get :syms shdr) (readelf--read-symtab shdr)))
  (goto-char (cdr (alist-get :header shdr)))
  (dolist (sym (alist-get :syms shdr))
    (-let* (((&alist 'name 'index 'other 'shndx 'value 'size) sym))
      ;; TODO - show section, filter irrelevant stuf,
      ;; print symbol type, link to disassembly?
      (insert (format "0x%08x\t%s\n" value name)))))

(defun readelf--expander/phdr (phdr)
  (let ((type (alist-get 'type phdr)))
    (cond
     ((= type readelf--p_type/PT_NOTE) 'readelf--expand-pt-note)
     (t nil))))


(defun readelf--expander/shdr (shdr)
  (let ((type (alist-get 'type shdr)))
    (cond
     ((= type readelf--sh_type/SHT_SYMTAB) 'readelf--expand-symtab)
     (t nil))))

(defun readelf--pp-phdr (phdr)
  (let* ((type (cdr (assq 'type phdr)))
         (beg (point))
         (expansible? (readelf--expander/phdr phdr))
         (sigil (if expansible? "+" " ")))
    (insert sigil " phdr of type: " (or (readelf--p_type-name type) (format "0x%x" type)) "\n")
    (setf (alist-get :header phdr) `(,beg . ,(point)))
    (put-text-property beg (point) :phdr phdr)))


(defun readelf--pp-shdr (shdr)
  (let ((type (alist-get 'type shdr)))
    (when (/= type readelf--sh_type/SHT_NULL)
      (let* ((name (alist-get 'name shdr))
             (beg (point))
             (expansible? (readelf--expander/shdr shdr))
             (sigil (if expansible? "+" " ")))
        (insert sigil " shdr: " name " type: " (or (readelf--sh_type-name type) (format "0x%x" type)) "\n")
        (setf (alist-get :header shdr) `(,beg . ,(point)))
        (put-text-property beg (point) :shdr shdr)))))

(defun readelf--get-phdrs ()
  (let ((phnum (cdr (assq 'phnum readelf-header)))
        (phoff (cdr (assq 'phoff readelf-header)))
        (phentsize (cdr (assq 'phentsize readelf-header))))
    (when (= phnum #xffff)
      (error "PH_XNUM not yet supported"))
    (mapcar
     (lambda (i)
       (let* ((offset (+ phoff (* i phentsize)))
              (phdr
               (with-current-buffer readelf-fbuf
                 (buffer-substring-no-properties (+ offset 1) (+ offset phentsize 1)))))
         (bindat-unpack readelf-le64-phdr-bindat-spec phdr)))
     (number-sequence 0 (1- phnum)))))

(defun readelf--get-shdrs ()
  (let ((shnum (cdr (assq 'shnum readelf-header)))
        (shoff (cdr (assq 'shoff readelf-header)))
        (shentsize (cdr (assq 'shentsize readelf-header))))
    (when (>= shnum #xff00)
      (error "SHN_LORESERVE not yet supported"))
    (let ((shdrs (mapcar
                  (lambda (i)
                    (let* ((offset (+ shoff (* i shentsize)))
                           (shdr
                            (with-current-buffer readelf-fbuf
                              (buffer-substring-no-properties (+ offset 1) (+ offset shentsize 1)))))
                      (bindat-unpack readelf-le64-shdr-bindat-spec shdr)))
                  (number-sequence 0 (1- shnum)))))
      (let* ((shstrndx (alist-get 'shstrndx readelf-header))
             (shstrbase (bindat-get-field shdrs shstrndx 'offset)))
        (dolist (shdr shdrs)
          (when (/= (alist-get 'type shdr) readelf--sh_type/SHT_NULL)
            (let* ((name (alist-get 'name shdr))
                   (name-str
                    (with-current-buffer readelf-fbuf
                      (readelf--cstr (+ shstrbase name 1)))))
              (setf (alist-get 'name shdr) name-str))))
        shdrs))))

;; offset is 1-indexed!
(defun readelf--cstr (offset &optional max)
  (let ((end offset)
        (rem max))
    (while (and
            (/= (char-after end) 0)
            (or (not rem) (> rem 0)))
      (when rem (setq rem (1- rem)))
      (setq end (1+ end)))
    (when (/= (char-after end) 0)
      (error "overflow"))
    (buffer-substring-no-properties offset end)))


(defun readelf--is-text (shdr)
  (equal (alist-get 'name shdr) ".text"))


;; e.g. `(readelf--binsrch (lambda (x) (< 123 x)) [0 1 2 122 124 125])'
;; returns 122
(defun readelf--binsrch (pred v)
  (let ((r (length v))
        (l 0))
    (if (or (= r 0) (funcall pred (elt v 0))) nil
      (while (< (1+ l) r)
        (let ((cand (/ (+ l r) 2)))
          (if (funcall pred (elt v cand))
              (setq r cand)
            (setq l cand))))
      (elt v l))))

(defun readelf--getsym (addr)
  (when readelf-symtab
    (unless (alist-get :syms readelf-symtab)
      (setf (alist-get :syms readelf-symtab) (readelf--read-symtab readelf-symtab))))
  (readelf--binsrch
          (lambda (x)
            (< addr (car x)))
          readelf-symarray))

(defun readelf--symbolize (addr)  
  (let ((elt (readelf--getsym addr)))
    (and elt
         (let ((diff (- addr (car elt))))
           (if (= diff 0) (cdr elt)
             (format "%s+0x%x" (cdr elt) diff))))))

(defconst readelf--arm64-operand-symbols
  `((adrp (reg imm) . 1)
    (cbz (reg imm) . 1)
    (cbnz (reg imm) . 1)
    (tbz (reg imm imm) . 2)
    (tbnz (reg imm imm) . 2)
    (b (imm) . 0)
    ,@(mapcar
       (lambda (cc)
         `(,(intern (format "b.%s" cc)) (imm) . 0))
       '(eq ne cs hs cc lo mi pl vs vc hi ls ge lt gt le al))
    (bl (imm) . 0)
    ))

(defun readelf--symbolizable-addr (insn)
  (let* ((mnemonic (intern (struct-capstone-insn-mnemonic insn)))
         (pattern-and-idx (alist-get mnemonic readelf--arm64-operand-symbols))
         (pattern (car pattern-and-idx))
         (idx (cdr pattern-and-idx))
         (ops (struct-capstone-insn-ops insn))
         (p pattern)
         (o ops)
         fail
         found
         (i 0))
    (while (or p o)
      (let ((pn (car p))
            (on (car o)))
        (if (not (eq pn (car on)))
            (setq fail t p nil o nil)
          (when (= i idx)
            (setq found (cadr on))))
        (setq p (cdr p) o (cdr o) i (1+ i))))
    (and (not fail) found)))

(defun btv-fmtinsn (insn)
  (let* ((size (struct-capstone-insn-size insn))
         (mnemonic (struct-capstone-insn-mnemonic insn))
         (opstr (struct-capstone-insn-op_str insn))
         (address (struct-capstone-insn-address insn))
         (bytes (struct-capstone-insn-bytes insn))
         (symbolizable-addr (readelf--symbolizable-addr insn))
         (symbolized
          (and symbolizable-addr               
               (readelf--symbolize symbolizable-addr))))
    (propertize (format "%s %s %s%s\n"
                        (propertize (format "0x%.8x:" address) 'font-lock-face 'readelf-disasm-addr)
                        mnemonic
                        opstr
                        (if symbolized
                            (concat (propertize " ; " 'font-lock-face 'font-lock-comment-face)
                                    (propertize symbolized 'font-lock-face 'link))
                          ""))
                'readelf-disasm-position address
                'readelf-disasm-link-target symbolizable-addr)))

(defun readelf--mk-disas-buf (shdr)
  (let* ((start (1+ (alist-get 'offset shdr)))
         (sz (alist-get 'size shdr))
         (end (+ start sz))
         (addr (alist-get 'addr shdr))
         (ss (with-current-buffer readelf-fbuf (buffer-substring-no-properties start end)))
         (code (capstone-vector-from-buffer readelf-fbuf (alist-get 'offset shdr) (alist-get 'size shdr)))
         (bufname (format "*disasm* %s" readelf-filename))
         (buf (with-current-buffer (generate-new-buffer bufname)
                (readelf-disasm-mode)
                (setq-local readelf-disasm--extents `((,addr . ,(+ addr sz))))
                (current-buffer)))
         (handle
          (or (and (boundp 'readelf-disas-handle) readelf-disas-handle)
              (setq-local readelf-disas-handle (capstone-open capstone-CS_ARCH_ARM64 capstone-CS_MODE_LITTLE_ENDIAN)))))
    (capstone-option handle capstone-CS_OPT_DETAIL capstone-CS_OPT_ON)
    (capstone-with-disasm
     (disas
      code
      addr
      0
      :arm64
      nil
      handle)
     (mapc 
      (lambda (insn)
        (let* ((addr (struct-capstone-insn-address insn))
               (sym (readelf--getsym addr)))
          (when (and sym (= (car sym) addr))
            (readelf--wcb buf (insert (format "%s:\n" (propertize (cdr sym) 'sym sym 'font-lock-face 'readelf-disasm-symbol-header))))))
        (let ((f (btv-fmtinsn insn)))
          (readelf--wcb buf
            (insert f))))
      (mapcar #'capstone-insn disas)))    
    buf))

;; TODO - check if capstone is available first?
(defun readelf-jump-to-disasm (&optional force)
  (interactive)
  (require 'emacs-capstone)
  (let* ((s (get-text-property (point) :shdr))
         (b
          (and s
               (or
                (let ((b (get-text-property (point) :disas-buf)))
                  (and (buffer-live-p b) b))
                (and
                 (or force (readelf--is-text s))
                 (readelf--mk-disas-buf s)))))
         (hbegin (and s (car (alist-get :header s))))
         (hend (and s (cdr (alist-get :header s)))))
    (when (and hbegin hend)
      (let ((inhibit-read-only t))
        (put-text-property hbegin hend :disas-buf b)))
    (when b
      (switch-to-buffer b)
      (goto-char (point-min)))))

(defun readelf-toggle-expand ()
  (interactive)
  (let* ((p (get-text-property (point) :phdr))
         (s (get-text-property (point) :shdr))
         (x? (if p (readelf--expander/phdr p) (readelf--expander/shdr s)))
         (g (or p s))
         (xx (and g (alist-get :expanded-extent g)))
         (hbegin (and g (car (alist-get :header g))))
         (hend (and g (cdr (alist-get :header g))))
         (inhibit-read-only t))
    (when (and g x?)
      (if xx
          ;; We are already expanded, so collapse
          (save-excursion
            (delete-region hend xx)
            (goto-char hbegin)
            (delete-char 1)
            (insert "+")
            (put-text-property hbegin hend
                               (if p :phdr :shdr)
                               (assq-delete-all :expanded-extent g)))
        (let ((xf (if p
                      (readelf--expander/phdr p)
                    (readelf--expander/shdr s))))
          (save-excursion
            (goto-char hbegin)
            (delete-char 1)
            (insert "-"))
          (save-excursion
            (funcall xf g)
            (put-text-property hbegin hend
                               (if p :phdr :shdr)
                               (cons `(:expanded-extent . ,(point)) g))))))))

(defvar readelf-mode-map
  (let ((map (make-keymap)))
    (suppress-keymap map t)
    (keymap-set map "TAB" #'readelf-toggle-expand)
    (keymap-set map "RET" #'readelf-toggle-expand)
    (keymap-set map "d" #'readelf-jump-to-disasm)
    map))

(defun readelf--delete-fbuf ()
  (kill-buffer readelf-fbuf))

(define-derived-mode readelf-mode special-mode "Readelf Mode"
  :interactive nil
  (buffer-disable-undo)
  (add-hook 'kill-buffer-hook #'readelf--delete-fbuf nil t)
  (setq buffer-read-only t)
  (let* ((fbuf
          ;; TODO - is there a way to avoid reading the
          ;; whole file into a buffer?
          (generate-new-buffer " *readelf internal*" t))
         (h (with-current-buffer fbuf
              (set-buffer-multibyte nil)
              (let ((coding-system-for-read 'binary))
                (insert-file-contents-literally filename))
              (readelf-validate-header (readelf-get-header)))))
    (setq-local readelf-header h)
    (setq-local readelf-fbuf fbuf))
  (setq-local readelf-phdrs (readelf--get-phdrs))
  (setq-local readelf-shdrs (readelf--get-shdrs))

  (setq-local readelf-strtab
              (cl-find-if
               (lambda (shdr)
                 (equal ".strtab"
                        (alist-get 'name shdr)))
               readelf-shdrs))

  (setq-local readelf-symtab
              (cl-find-if
               (lambda (shdr)
                 (equal ".symtab"
                        (alist-get 'name shdr)))
               readelf-shdrs))
  
  (setq-local readelf-filename filename)
  (setq-local readelf-symarray [])
  
  (let* ((print-length nil)
         (inhibit-read-only t)
         (shstrndx (cdr (assq 'shstrndx readelf-header)))
         (shstrbase
          (cdr (assq 'offset (nth shstrndx readelf-shdrs)))))
    (dolist (phdr readelf-phdrs)
      (readelf--pp-phdr phdr))
    (dolist (shdr readelf-shdrs)
      (readelf--pp-shdr shdr))))

(defun readelf (filename)
  (interactive
   (list(read-file-name
  	 "ELF file: " nil default-directory)))
  (let* ((bufname (format "*readelf* %s" filename))
         (buf (generate-new-buffer bufname)))
    (with-current-buffer buf
      (readelf-mode)      
      (switch-to-buffer buf)
      (goto-char (point-min))
      )))

