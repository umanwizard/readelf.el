(require 'bindat)

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


(defun readelf--pp-phdr (phdr)
  (let ((type (cdr (assq 'type phdr))))
    (insert "phdr of type: " (or (readelf--p_type-name type) (format "0x%x" type)) "\n")))


(defun readelf--pp-shdr (shdr getstr)
  (let ((type (cdr (assq 'type shdr))))
    (when (/= type readelf--sh_type/SHT_NULL)
      (let ((name (funcall getstr (cdr (assq 'name shdr)))))
        (insert "shdr: " name " type: " (or (readelf--sh_type-name type) (format "0x%x" type)) "\n")))))

(defun readelf--get-phdrs (h)
  (let ((phnum (cdr (assq 'phnum h)))
        (phoff (cdr (assq 'phoff h)))
        (phentsize (cdr (assq 'phentsize h))))
    (when (= phnum #xffff)
      (error "PH_XNUM not yet supported"))
    (mapcar
     (lambda (i)
       (let* ((offset (+ phoff (* i phentsize)))
              (phdr
               (buffer-substring-no-properties (+ offset 1) (+ offset phentsize 1))))
         (bindat-unpack readelf-le64-phdr-bindat-spec phdr)))
     (number-sequence 0 (1- phnum)))))

(defun readelf--get-shdrs (h)
  (let ((shnum (cdr (assq 'shnum h)))
        (shoff (cdr (assq 'shoff h)))
        (shentsize (cdr (assq 'shentsize h))))
    (when (>= shnum #xff00)
      (error "SHN_LORESERVE not yet supported"))
    (mapcar
     (lambda (i)
       (let* ((offset (+ shoff (* i shentsize)))
              (shdr
               (buffer-substring-no-properties (+ offset 1) (+ offset shentsize 1))))
         (bindat-unpack readelf-le64-shdr-bindat-spec shdr)))
     (number-sequence 0 (1- shnum)))))

;; offset is 1-indexed!
(defun readelf--cstr (offset)
  (let ((end offset))
    (while (/= (char-after end) 0)
      (setq end (1+ end)))
    (buffer-substring-no-properties offset end)))

(defun readelf (filename)
  (interactive
   (list(read-file-name
  	 "ELF file: " nil default-directory)))
  (let* ((bufname (format "*readelf* %s" filename))
         (buf (generate-new-buffer bufname))
         ;; TODO - is there a way to avoid reading the
         ;; whole file into a buffer?
         ;;
         ;; Also, how do we avoid this being visible to the user?
         (fbuf (generate-new-buffer filename t)))
    (let ((h (with-current-buffer fbuf
               (set-buffer-multibyte nil)
               (let ((coding-system-for-read 'binary))
                 (insert-file-contents-literally filename))
               (readelf-validate-header (readelf-get-header)))))
      (with-current-buffer buf        
        (setq buffer-read-only t)
        (setq-local readelf-header h)
        (setq-local readelf-phdrs
                    (with-current-buffer fbuf (readelf--get-phdrs h)))
        (setq-local readelf-shdrs
                    (with-current-buffer fbuf (readelf--get-shdrs h)))
        
        (let* ((print-length nil)
              (inhibit-read-only t)
              (shstrndx (cdr (assq 'shstrndx h)))
              (shstrbase
               (cdr (assq 'offset (nth shstrndx readelf-shdrs)))))
          (pp h buf)
          (dolist (phdr readelf-phdrs)
            (readelf--pp-phdr phdr))
          (dolist (shdr readelf-shdrs)
            (readelf--pp-shdr
             shdr
             (lambda (offset)
               (with-current-buffer fbuf
                 (readelf--cstr (+ shstrbase offset 1)))))))))))
