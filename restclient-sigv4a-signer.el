;;; restclient-sigv4a-signer.el --- SigV4A ECDSA-P256-SHA256 signing algorithm  -*- lexical-binding: t; -*-

;; Copyright (C) 2026  Sunil Murthy

;; This file is not part of GNU Emacs.

;;; Commentary:

;; Implements the AWS Signature Version 4 Asymmetric (SigV4A) signing
;; algorithm using ECDSA with the P-256 curve and SHA-256 digest.
;;
;; This module delegates ECDSA operations (key derivation scalar
;; validation and signing) to the OpenSSL CLI via subprocess calls,
;; keeping the rest of the signing logic in pure Emacs Lisp.
;;
;; External dependency:
;;   - OpenSSL 1.1+ CLI (`openssl` binary must be in PATH)
;;   - Only required when SigV4A signing is actually invoked
;;   - Install via your system package manager:
;;     - macOS: brew install openssl
;;     - Debian/Ubuntu: apt install openssl
;;     - Fedora/RHEL: dnf install openssl

;;; Code:

(require 'cl-lib)
(require 'restclient-sigv4-signer)

;;; Constants

(defconst restclient-sigv4a--p256-order-hex
  "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
  "P-256 curve order (n) in hex.")

;;; Dependency Check

(defun restclient-sigv4a--check-openssl ()
  "Verify that openssl CLI is available.
Signals error with installation instructions if not found."
  (unless (executable-find "openssl")
    (error "restclient-sigv4a: signer: openssl not found (required for SigV4A signing). Install OpenSSL 1.1+ and ensure 'openssl' is in PATH.")))

;;; Hex Comparison Utilities

(defun restclient-sigv4a--hex-less-than (hex-a hex-b)
  "Return non-nil if HEX-A represents a smaller number than HEX-B.
Both HEX-A and HEX-B must be lowercase hex strings of equal length."
  (string< hex-a hex-b))

(defun restclient-sigv4a--hex-is-zero (hex-str)
  "Return non-nil if HEX-STR represents zero."
  (string= hex-str (make-string (length hex-str) ?0)))

;;; Key Derivation

(defconst restclient-sigv4a--key-derivation-label
  "AWS4-ECDSA-P256-SHA256"
  "Label string used in SigV4A key derivation fixed-input.")

(defun restclient-sigv4a--scalar-to-pem (scalar-hex)
  "Convert a raw P-256 scalar (as hex string) to PEM EC private key.
Uses openssl to construct a valid EC private key from the raw scalar.
Returns the PEM string.  Signals error if openssl fails."
  (let ((tmp-der (make-temp-file "sigv4a-key-" nil ".der"))
        (tmp-pem nil))
    (unwind-protect
        (let* (;; Build ASN.1 DER for EC private key:
               ;; SEQUENCE {
               ;;   INTEGER 1 (version)
               ;;   OCTET STRING (32 bytes private key)
               ;;   [0] OID prime256v1 (1.2.840.10045.3.1.7)
               ;; }
               ;; We use openssl ec to convert from a raw key format.
               ;; First, build a minimal DER structure with the scalar and curve OID.
               (scalar-bytes (decode-hex-string scalar-hex))
               ;; ASN.1 DER encoding of EC private key (RFC 5915)
               ;; 30 (SEQUENCE) + length
               ;;   02 01 01 (INTEGER version=1)
               ;;   04 20 <32-byte-scalar> (OCTET STRING)
               ;;   a0 0a (context [0] explicit, length 10)
               ;;     06 08 2a 86 48 ce 3d 03 01 07 (OID 1.2.840.10045.3.1.7 = prime256v1)
               (oid-bytes (decode-hex-string "06082a8648ce3d030107"))
               (version-bytes (decode-hex-string "020101"))
               (scalar-tlv (concat (unibyte-string #x04 (length scalar-bytes)) scalar-bytes))
               (oid-context (concat (unibyte-string #xa0 (length oid-bytes)) oid-bytes))
               (seq-content (concat version-bytes scalar-tlv oid-context))
               (der-bytes (concat (unibyte-string #x30 (length seq-content)) seq-content)))
          ;; Write DER to temp file
          (with-temp-file tmp-der
            (set-buffer-multibyte nil)
            (insert der-bytes))
          ;; Convert DER to PEM using openssl
          (setq tmp-pem (make-temp-file "sigv4a-pem-" nil ".pem"))
          (let ((exit-code
                 (call-process "openssl" nil nil nil
                               "ec" "-inform" "DER" "-in" tmp-der
                               "-outform" "PEM" "-out" tmp-pem)))
            (unless (= exit-code 0)
              (error "restclient-sigv4a: signer: openssl ec key conversion failed (exit %d)" exit-code)))
          ;; Read PEM content
          (with-temp-buffer
            (insert-file-contents tmp-pem)
            (buffer-string)))
      ;; Cleanup
      (when (file-exists-p tmp-der)
        (delete-file tmp-der))
      (when (and tmp-pem (file-exists-p tmp-pem))
        (delete-file tmp-pem)))))

(defun restclient-sigv4a--derive-ec-key (access-key-id secret-access-key)
  "Derive ECDSA P-256 key pair from ACCESS-KEY-ID and SECRET-ACCESS-KEY.
Uses counter-based HMAC-SHA256 loop per AWS SigV4A specification.
Returns a plist (:private-key-pem PEM-STRING) or signals error.

Algorithm:
  1. key = \"AWS4A\" + secret-access-key
  2. For counter = 1 to 254:
     a. fixed-input = access-key-id + counter-byte + label
     b. candidate = HMAC-SHA256(key, fixed-input)
     c. If candidate < P-256 order (n) and candidate > 0: valid scalar found
  3. Convert scalar to PEM-format EC private key via openssl subprocess
  4. Signal error if no valid scalar found in 254 attempts."
  (restclient-sigv4a--check-openssl)
  (let* ((hmac-key (concat "AWS4A" secret-access-key))
         (label restclient-sigv4a--key-derivation-label)
         (counter 1)
         (found-scalar nil))
    ;; Loop counter from 1 to 254
    (while (and (not found-scalar) (<= counter 254))
      (let* ((fixed-input (concat access-key-id
                                  (unibyte-string counter)
                                  label))
             (candidate-bin (restclient-sigv4-hmac-sha256 hmac-key fixed-input))
             (candidate-hex (encode-hex-string candidate-bin)))
        ;; Check: candidate > 0 and candidate < P-256 order
        (when (and (not (restclient-sigv4a--hex-is-zero candidate-hex))
                   (restclient-sigv4a--hex-less-than candidate-hex
                                                     restclient-sigv4a--p256-order-hex))
          (setq found-scalar candidate-hex)))
      (setq counter (1+ counter)))
    ;; If no valid scalar found, signal error
    (unless found-scalar
      (error "restclient-sigv4a: signer: key derivation failed for access key '%s' after 254 attempts"
             access-key-id))
    ;; Convert scalar to PEM EC private key
    (list :private-key-pem (restclient-sigv4a--scalar-to-pem found-scalar))))

(provide 'restclient-sigv4a-signer)
;;; restclient-sigv4a-signer.el ends here
