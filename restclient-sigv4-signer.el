;;; restclient-sigv4-signer.el --- SigV4 signing algorithm  -*- lexical-binding: t; -*-

;; Copyright (C) 2026  Sunil Murthy

;; This file is not part of GNU Emacs.

;;; Commentary:

;; Implements the AWS Signature Version 4 signing algorithm including
;; canonical request construction, string-to-sign building, signing key
;; derivation, and signature computation.

;;; Code:

(defun restclient-sigv4-sha256 (data)
  "Compute SHA-256 hash of DATA.
DATA is a string (or nil, treated as empty string).
Returns lowercase hex string."
  (condition-case err
      (secure-hash 'sha256 (or data ""))
    (error
     (error "restclient-sigv4: signer: SHA-256 failed: %s"
            (error-message-string err)))))

(defun restclient-sigv4-hmac-sha256 (key data)
  "Compute HMAC-SHA256 of DATA with KEY.
KEY and DATA are strings (KEY may be binary/unibyte).
Returns binary string."
  (condition-case err
      (gnutls-hash-mac 'SHA256 key data)
    (error
     (error "restclient-sigv4: signer: HMAC-SHA256 failed: %s"
            (error-message-string err)))))

;;; URI Encoding

(defun restclient-sigv4-uri-encode (str &optional encode-slash)
  "URI-encode STR per RFC 3986 unreserved character set.
Unreserved characters (A-Z, a-z, 0-9, -, _, ., ~) pass through unencoded.
All other characters are percent-encoded as %XX (uppercase hex).
When ENCODE-SLASH is non-nil, forward slashes are also percent-encoded.
Multi-byte characters are encoded byte-by-byte using UTF-8 encoding."
  (let* ((bytes (encode-coding-string str 'utf-8))
         (len (length bytes))
         (result (make-string 0 0))
         (i 0))
    (while (< i len)
      (let ((byte (aref bytes i)))
        (cond
         ;; RFC 3986 unreserved characters pass through
         ((or (and (>= byte ?A) (<= byte ?Z))
              (and (>= byte ?a) (<= byte ?z))
              (and (>= byte ?0) (<= byte ?9))
              (= byte ?-)
              (= byte ?_)
              (= byte ?.)
              (= byte ?~))
          (setq result (concat result (char-to-string byte))))
         ;; Forward slash: encode only when encode-slash is non-nil
         ((= byte ?/)
          (if encode-slash
              (setq result (concat result "%2F"))
            (setq result (concat result "/"))))
         ;; All other bytes get percent-encoded
         (t
          (setq result (concat result (format "%%%02X" byte))))))
      (setq i (1+ i)))
    result))

(provide 'restclient-sigv4-signer)
;;; restclient-sigv4-signer.el ends here
