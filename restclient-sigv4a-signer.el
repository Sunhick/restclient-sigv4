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

(defconst restclient-sigv4a--n-minus-two-hex
  "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f"
  "P-256 curve order minus 2 (n - 2) in hex.
Used for key derivation comparison per FIPS 186-4 Appendix B.4.2.")

(defun restclient-sigv4a--derive-hmac-key (bit-len key label context)
  "Derive key using NIST SP 800-108 KDF in Counter Mode with HMAC-SHA256.
BIT-LEN is the desired output length in bits.
KEY is the HMAC key (binary string).
LABEL is the label byte string.
CONTEXT is the context byte string.
Returns a binary string of BIT-LEN/8 bytes.

The fixed input is: label || 0x00 || context || int32(bitLen).
The HMAC input for each iteration is: int32(i) || fixedInput."
  (let* ((fixed-input (concat label
                              (unibyte-string #x00)
                              context
                              ;; int32(bitLen) big-endian
                              (unibyte-string (logand (ash bit-len -24) #xff)
                                              (logand (ash bit-len -16) #xff)
                                              (logand (ash bit-len -8) #xff)
                                              (logand bit-len #xff))))
         ;; For 256-bit output with SHA-256 (32 bytes), we need exactly 1 iteration
         (counter-bytes (unibyte-string 0 0 0 1))
         (hmac-input (concat counter-bytes fixed-input))
         (output (restclient-sigv4-hmac-sha256 key hmac-input)))
    (substring output 0 (/ bit-len 8))))

(defun restclient-sigv4a--big-int-add-one-hex (hex-str)
  "Add 1 to the big integer represented by HEX-STR.
Returns the result as a hex string of the same length."
  (let* ((bytes (decode-hex-string hex-str))
         (carry 1)
         (i (1- (length bytes))))
    (while (and (>= i 0) (> carry 0))
      (let ((sum (+ (aref bytes i) carry)))
        (aset bytes i (logand sum #xff))
        (setq carry (ash sum -8)))
      (setq i (1- i)))
    (encode-hex-string bytes)))

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
               (scalar-bytes (decode-hex-string scalar-hex))
               ;; ASN.1 DER encoding of EC private key (RFC 5915)
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
Uses NIST SP 800-108 KDF in Counter Mode per AWS SigV4A specification,
based on FIPS 186-4 Appendix B.4.2.
Returns a plist (:private-key-pem PEM-STRING) or signals error.

Algorithm:
  1. inputKey = \"AWS4A\" + secret-access-key
  2. For external counter = 1 to 254:
     a. context = access-key-id + external-counter-byte
     b. candidate = KDF(inputKey, label=\"AWS4-ECDSA-P256-SHA256\", context, bitLen=256)
     c. If candidate <= (n - 2): d = candidate + 1, valid scalar found
  3. Convert scalar d to PEM-format EC private key via openssl subprocess
  4. Signal error if no valid scalar found in 254 attempts."
  (restclient-sigv4a--check-openssl)
  (let* ((input-key (concat "AWS4A" secret-access-key))
         (label restclient-sigv4a--key-derivation-label)
         (ext-counter 1)
         (found-scalar nil))
    ;; Loop external counter from 1 to 254
    (while (and (not found-scalar) (<= ext-counter 254))
      (let* ((context (concat access-key-id (unibyte-string ext-counter)))
             (candidate-bin (restclient-sigv4a--derive-hmac-key
                             256 input-key label context))
             (candidate-hex (encode-hex-string candidate-bin)))
        ;; Check: candidate <= (n - 2)
        ;; i.e., candidate < (n - 2) OR candidate == (n - 2)
        (when (or (restclient-sigv4a--hex-less-than candidate-hex
                                                     restclient-sigv4a--n-minus-two-hex)
                  (string= candidate-hex restclient-sigv4a--n-minus-two-hex))
          ;; d = candidate + 1
          (setq found-scalar (restclient-sigv4a--big-int-add-one-hex candidate-hex))))
      (setq ext-counter (1+ ext-counter)))
    ;; If no valid scalar found, signal error
    (unless found-scalar
      (error "restclient-sigv4a: signer: key derivation failed for access key '%s' after 254 attempts"
             access-key-id))
    ;; Convert scalar to PEM EC private key
    (list :private-key-pem (restclient-sigv4a--scalar-to-pem found-scalar))))

;;; ECDSA Signing

(defun restclient-sigv4a--ecdsa-sign (private-key-pem message)
  "Sign MESSAGE using ECDSA-P256-SHA256 with PRIVATE-KEY-PEM.
Calls openssl dgst -sha256 -sign via subprocess.
Returns DER-encoded signature as a unibyte string.
Signals error if openssl is not available or signing fails."
  (restclient-sigv4a--check-openssl)
  (let ((keyfile (make-temp-file "sigv4a-sign-" nil ".pem"))
        (stderr-file (make-temp-file "sigv4a-stderr-" nil ".txt")))
    (unwind-protect
        (progn
          ;; Write PEM key to temp file with restrictive permissions
          (set-file-modes keyfile #o600)
          (with-temp-file keyfile
            (insert private-key-pem))
          ;; Sign the message via openssl subprocess
          (with-temp-buffer
            (set-buffer-multibyte nil)
            (let* ((msg-bytes (encode-coding-string message 'utf-8))
                   (exit-code
                    (let ((coding-system-for-read 'binary)
                          (coding-system-for-write 'binary))
                      (insert msg-bytes)
                      (call-process-region (point-min) (point-max)
                                          "openssl"
                                          t          ; delete input region
                                          (list (current-buffer) stderr-file)
                                          nil        ; don't redisplay
                                          "dgst" "-sha256"
                                          "-sign" keyfile
                                          "-binary"))))
              (if (= exit-code 0)
                  (buffer-string)
                ;; Read stderr for error details
                (error "restclient-sigv4a: signer: ECDSA signing failed: %s"
                       (with-temp-buffer
                         (insert-file-contents stderr-file)
                         (string-trim (buffer-string))))))))
      ;; Clean up temp files
      (when (file-exists-p keyfile)
        (delete-file keyfile))
      (when (file-exists-p stderr-file)
        (delete-file stderr-file)))))

;;; String-to-Sign and Authorization Header Assembly

(defun restclient-sigv4a--credential-scope (datestamp service)
  "Build SigV4A credential scope without region.
DATESTAMP is the date string in YYYYMMDD format.
SERVICE is the AWS service string.
Returns string in format: <datestamp>/<service>/aws4_request."
  (concat datestamp "/" service "/aws4_request"))

(defun restclient-sigv4a--string-to-sign (timestamp datestamp service canonical-request-hash)
  "Construct the SigV4A string-to-sign.
TIMESTAMP is the request timestamp in YYYYMMDDTHHMMSSZ format.
DATESTAMP is the date string in YYYYMMDD format.
SERVICE is the AWS service string.
CANONICAL-REQUEST-HASH is the hex-encoded SHA-256 hash of the serialized canonical request.
Returns the string-to-sign with four newline-separated parts:
  1. Algorithm identifier: AWS4-ECDSA-P256-SHA256
  2. Timestamp: YYYYMMDDTHHMMSSZ
  3. Credential scope: <datestamp>/<service>/aws4_request
  4. Canonical request hash: hex(SHA256(canonical-request))"
  (let ((scope (restclient-sigv4a--credential-scope datestamp service)))
    (concat "AWS4-ECDSA-P256-SHA256" "\n"
            timestamp "\n"
            scope "\n"
            canonical-request-hash)))

(defun restclient-sigv4a--authorization-header (access-key-id datestamp service signed-headers der-signature)
  "Assemble the SigV4A Authorization header value.
ACCESS-KEY-ID is the AWS access key ID string.
DATESTAMP is the date string in YYYYMMDD format.
SERVICE is the AWS service string.
SIGNED-HEADERS is the semicolon-separated list of signed header names.
DER-SIGNATURE is the DER-encoded ECDSA signature as a unibyte string.
Returns the full Authorization header value in the format:
  AWS4-ECDSA-P256-SHA256 Credential=<id>/<scope>, SignedHeaders=<sh>, Signature=<hex>"
  (let ((scope (restclient-sigv4a--credential-scope datestamp service))
        (signature-hex (encode-hex-string der-signature)))
    (concat "AWS4-ECDSA-P256-SHA256 "
            "Credential=" access-key-id "/" scope ", "
            "SignedHeaders=" signed-headers ", "
            "Signature=" signature-hex)))

;;; Public Signing Function

(defun restclient-sigv4a-sign-request (method url headers body credential region-set service timestamp)
  "Sign a request using SigV4A and return updated headers alist.
METHOD: HTTP method string.
URL: full request URL.
HEADERS: alist of (name . value) pairs.
BODY: request body string or nil.
CREDENTIAL: plist (:access-key-id K :secret-access-key S :session-token T).
REGION-SET: comma-separated region string or \"*\".
SERVICE: AWS service string.
TIMESTAMP: UTC time value or nil for current time.
Returns updated headers alist with Authorization, x-amz-date,
x-amz-content-sha256, x-amz-region-set, and optionally x-amz-security-token."
  ;; Check openssl availability at entry
  (restclient-sigv4a--check-openssl)
  (let* ((access-key-id (plist-get credential :access-key-id))
         (secret-access-key (plist-get credential :secret-access-key))
         (session-token (plist-get credential :session-token))
         ;; Derive EC key from credentials
         (ec-key (restclient-sigv4a--derive-ec-key access-key-id secret-access-key))
         (private-key-pem (plist-get ec-key :private-key-pem))
         ;; Compute timestamps using existing utilities from restclient-sigv4-signer
         (amz-date (restclient-sigv4--format-timestamp timestamp))
         (datestamp (restclient-sigv4--format-datestamp timestamp))
         ;; Compute body hash
         (body-hash (restclient-sigv4-sha256 (or body "")))
         ;; Parse URL
         (url-parts (restclient-sigv4--parse-url url))
         (host (plist-get url-parts :host))
         (path (plist-get url-parts :path))
         (query-params (plist-get url-parts :query-params))
         ;; URI-encode the path (each segment individually, preserve trailing slash)
         (canonical-path
          (let* ((has-trailing-slash (and (> (length path) 1)
                                         (string-suffix-p "/" path)))
                 (segments (split-string path "/" t)))
            (if segments
                (let ((encoded (concat "/"
                                       (mapconcat (lambda (seg)
                                                    (restclient-sigv4-uri-encode seg t))
                                                  segments
                                                  "/"))))
                  (if has-trailing-slash
                      (concat encoded "/")
                    encoded))
              "/")))
         ;; Build headers for signing
         (signing-headers headers))
    ;; Add host if not already present
    (unless (cl-find "host" signing-headers
                     :key #'car
                     :test (lambda (a b) (string= (downcase a) (downcase b))))
      (setq signing-headers
            (cons (cons "host" host) signing-headers)))
    ;; Add x-amz-content-sha256
    (setq signing-headers
          (cons (cons "x-amz-content-sha256" body-hash) signing-headers))
    ;; Add x-amz-date
    (setq signing-headers
          (cons (cons "x-amz-date" amz-date) signing-headers))
    ;; Add x-amz-region-set
    (setq signing-headers
          (cons (cons "x-amz-region-set" region-set) signing-headers))
    ;; Conditionally add x-amz-security-token if session token present
    (when session-token
      (setq signing-headers
            (cons (cons "x-amz-security-token" session-token) signing-headers)))
    ;; Build canonical request using shared utility
    (let* ((creq (restclient-sigv4-canonical-request
                  method canonical-path query-params signing-headers body-hash))
           ;; Serialize and hash canonical request
           (creq-string (restclient-sigv4-serialize-canonical-request creq))
           (creq-hash (restclient-sigv4-sha256 creq-string))
           ;; Build string-to-sign (SigV4A variant: no region in scope)
           (string-to-sign (restclient-sigv4a--string-to-sign
                            amz-date datestamp service creq-hash))
           ;; Sign with ECDSA
           (der-signature (restclient-sigv4a--ecdsa-sign private-key-pem string-to-sign))
           ;; Get signed headers from canonical request
           (signed-headers (plist-get creq :signed-headers))
           ;; Build Authorization header
           (auth-header (restclient-sigv4a--authorization-header
                         access-key-id datestamp service signed-headers der-signature)))
      ;; Return updated headers alist with all required headers added
      (let ((result headers))
        ;; Add x-amz-date
        (setq result (cons (cons "x-amz-date" amz-date) result))
        ;; Add x-amz-content-sha256
        (setq result (cons (cons "x-amz-content-sha256" body-hash) result))
        ;; Add x-amz-region-set
        (setq result (cons (cons "x-amz-region-set" region-set) result))
        ;; Add x-amz-security-token if present
        (when session-token
          (setq result (cons (cons "x-amz-security-token" session-token) result)))
        ;; Add Authorization header
        (setq result (cons (cons "Authorization" auth-header) result))
        result))))

(provide 'restclient-sigv4a-signer)
;;; restclient-sigv4a-signer.el ends here
