(provide 'readelf-disasm)

(defface readelf-disasm-symbol-header
  '((t :weight bold))
  "Face for symbol names at the beginning of functions.")

(defface readelf-disasm-addr
  '((t :weight light))
  "Face for addresses in the left margin.")

(defun readelf-disasm--find-addr (target)
  (unless (cl-find-if (lambda (x) (and (<= (car x) target) (< target (cdr x)))) readelf-disasm--extents)
    (error "this address has not been disassembled"))
  ;; TODO [btv] perf? Profile it.
  (save-excursion
    (let ((l (point-min))
          (r (1+ (point-max))))
      (cl-assert (< l r))
      (while (< (1+ l) r)
        (let ((cand (/ (+ l r) 2)))
          (goto-char cand)
          (while (get-text-property (point) 'sym)
            (forward-line)
            (setq cand (point)))
          (let ((addr (get-text-property (point) 'readelf-disasm-position)))
            (if (< target addr)
                (setq r cand)
              (setq l cand)))))
      (goto-char l)
      (beginning-of-line)
      (point))))

(defun readelf-disasm-follow-link ()
  (interactive)
  (let ((target (get-text-property (point) 'readelf-disasm-link-target)))
    (when target
      (goto-char (readelf-disasm--find-addr target)))))

(defvar readelf-disasm-mode-map
  (let ((map (make-keymap)))
    (suppress-keymap map t)    
    (keymap-set map "RET" #'readelf-disasm-follow-link)
    map))

(define-derived-mode readelf-disasm-mode special-mode "Readelf-Disassembly Mode"
  :interactive nil
  (buffer-disable-undo)
  (setq buffer-read-only t)
  (let*
    )
)
