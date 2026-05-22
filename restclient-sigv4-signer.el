;;; restclient-sigv4-signer.el --- SigV4 signing algorithm  -*- lexical-binding: t; -*-

;; Copyright (C) 2026  Sunil Murthy

;; This file is not part of GNU Emacs.

;;; Commentary:

;; Implements the AWS Signature Version 4 signing algorithm including
;; canonical request construction, string-to-sign building, signing key
;; derivation, and signature computation.

;;; Code:

(require 'cl-lib)
(require 'hex-util)
(require 'url-parse)

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

;;; Canonical Request Construction

(defun restclient-sigv4--normalize-header-value (value)
  "Normalize header VALUE.
Trim leading/trailing whitespace and collapse consecutive spaces."
  (let ((trimmed (string-trim value)))
    (replace-regexp-in-string "  +" " " trimmed)))

(defun restclient-sigv4--canonical-query-string (query-params)
  "Build canonical query string from QUERY-PARAMS.
QUERY-PARAMS is a list of (name . value) pairs.
Each name and value is URI-encoded, then sorted by encoded name
first, then by encoded value for identical names.
Returns the joined string of encoded-name=encoded-value pairs separated by &."
  (if (null query-params)
      ""
    (let ((encoded-pairs
           (mapcar (lambda (pair)
                     (cons (restclient-sigv4-uri-encode (car pair) t)
                           (restclient-sigv4-uri-encode (cdr pair) t)))
                   query-params)))
      ;; Sort by encoded name ascending, then by encoded value ascending
      (setq encoded-pairs
            (sort encoded-pairs
                  (lambda (a b)
                    (if (string= (car a) (car b))
                        (string< (cdr a) (cdr b))
                      (string< (car a) (car b))))))
      (mapconcat (lambda (pair)
                   (concat (car pair) "=" (cdr pair)))
                 encoded-pairs
                 "&"))))

(defun restclient-sigv4--canonical-headers (headers)
  "Build canonical headers string and signed-headers list from HEADERS.
HEADERS is an alist of (name . value) pairs.
Returns a cons cell (canonical-headers-string . signed-headers-string)."
  (let* ((normalized
          (mapcar (lambda (h)
                    (cons (downcase (car h))
                          (restclient-sigv4--normalize-header-value (cdr h))))
                  headers))
         ;; Sort by lowercased name in ascending byte order
         (sorted (sort normalized
                      (lambda (a b)
                        (string< (car a) (car b)))))
         ;; Build canonical headers string: "name:value\n" for each
         (headers-str (mapconcat (lambda (h)
                                   (concat (car h) ":" (cdr h) "\n"))
                                 sorted
                                 ""))
         ;; Build signed headers: semicolon-separated sorted names
         (signed-headers (mapconcat #'car sorted ";")))
    (cons headers-str signed-headers)))

(defun restclient-sigv4-canonical-request (method path query-params headers body-hash)
  "Build canonical request struct from components.
METHOD is the HTTP method string.
PATH is the canonical URI path.
QUERY-PARAMS is a list of (name . value) pairs.
HEADERS is an alist of (name . value) pairs.
BODY-HASH is the hex-encoded SHA-256 hash of the body, or nil for empty body.
Returns a plist (:method :path :query :headers :signed-headers :body-hash)."
  (let* ((payload-hash (or body-hash
                           (restclient-sigv4-sha256 "")))
         ;; Ensure host is present in headers for signing
         (header-names (mapcar (lambda (h) (downcase (car h))) headers))
         (has-host (member "host" header-names))
         ;; Build canonical query string
         (canonical-query (restclient-sigv4--canonical-query-string query-params))
         ;; Build canonical headers and signed headers
         (header-result (restclient-sigv4--canonical-headers headers))
         (canonical-headers-str (car header-result))
         (signed-headers-str (cdr header-result)))
    ;; Verify host is in signed headers
    (unless has-host
      (error "restclient-sigv4: signer: host header must be included in request headers"))
    (list :method method
          :path path
          :query canonical-query
          :headers canonical-headers-str
          :signed-headers signed-headers-str
          :body-hash payload-hash)))

;;; Canonical Request Serialization

(defun restclient-sigv4-serialize-canonical-request (creq)
  "Serialize canonical request plist CREQ to string form.
CREQ is a plist with keys :method, :path, :query, :headers,
:signed-headers, :body-hash.
Returns a string with six sections separated by newlines:
  1. HTTP method
  2. Canonical URI (path)
  3. Canonical query string
  4. Canonical headers (each on its own line, followed by empty line)
  5. Signed headers (semicolon-separated)
  6. Payload hash"
  (concat (plist-get creq :method) "\n"
          (plist-get creq :path) "\n"
          (plist-get creq :query) "\n"
          (plist-get creq :headers) "\n"
          (plist-get creq :signed-headers) "\n"
          (plist-get creq :body-hash)))

(defun restclient-sigv4-parse-canonical-request (str)
  "Parse canonical request string STR back to plist.
STR must contain exactly six sections as produced by
`restclient-sigv4-serialize-canonical-request'.
Returns a plist (:method :path :query :headers :signed-headers :body-hash).
Signals error if STR is malformed."
  ;; The canonical request format is:
  ;;   METHOD\n
  ;;   PATH\n
  ;;   QUERY\n
  ;;   header1:value1\n
  ;;   header2:value2\n
  ;;   ...headerN:valueN\n
  ;;   \n
  ;;   signed-headers\n
  ;;   body-hash
  ;;
  ;; The headers section contains embedded newlines (one per header line),
  ;; terminated by a blank line. We parse by:
  ;; 1. Extract method (first line)
  ;; 2. Extract path (second line)
  ;; 3. Extract query (third line)
  ;; 4. Everything from line 4 until the first blank line is the headers section
  ;; 5. The line after the blank line is signed-headers
  ;; 6. The line after signed-headers is body-hash
  (let* ((lines (split-string str "\n"))
         (num-lines (length lines))
         method path query headers-str signed-headers body-hash)
    ;; We need at least 6 lines: method, path, query, (at least one header line),
    ;; empty line, signed-headers, body-hash
    ;; But minimum is: method, path, query, empty-line, signed-headers, body-hash = 6 lines
    ;; with no headers at all (empty headers section)
    (when (< num-lines 6)
      (error "restclient-sigv4: signer: invalid canonical request string (expected 6 sections, got %d)"
             (min num-lines 5)))
    ;; First three lines are straightforward
    (setq method (nth 0 lines))
    (setq path (nth 1 lines))
    (setq query (nth 2 lines))
    ;; Find the blank line that terminates the headers section.
    ;; Headers start at index 3. The blank line separates headers from signed-headers.
    (let ((blank-idx nil)
          (i 3))
      (while (and (< i num-lines) (null blank-idx))
        (when (string= (nth i lines) "")
          (setq blank-idx i))
        (setq i (1+ i)))
      (unless blank-idx
        (error "restclient-sigv4: signer: invalid canonical request string (expected 6 sections, got %d)"
               3))
      ;; Verify we have exactly 2 more lines after the blank line
      ;; (signed-headers and body-hash)
      (let ((remaining (- num-lines (1+ blank-idx))))
        (unless (= remaining 2)
          (error "restclient-sigv4: signer: invalid canonical request string (expected 6 sections, got %d)"
                 (+ 4 remaining))))
      ;; Build headers string: lines from index 3 to blank-idx (exclusive),
      ;; each terminated by newline
      (setq headers-str
            (if (= blank-idx 3)
                "" ;; no header lines
              (concat (mapconcat #'identity
                                 (cl-subseq lines 3 blank-idx)
                                 "\n")
                      "\n")))
      (setq signed-headers (nth (1+ blank-idx) lines))
      (setq body-hash (nth (+ blank-idx 2) lines)))
    (list :method method
          :path path
          :query query
          :headers headers-str
          :signed-headers signed-headers
          :body-hash body-hash)))

;;; Signing Key Derivation

(defun restclient-sigv4-derive-signing-key (secret-key date region service)
  "Derive SigV4 signing key by successively applying HMAC-SHA256.
SECRET-KEY is the AWS secret access key string.
DATE is the date string in YYYYMMDD format.
REGION is the AWS region string.
SERVICE is the AWS service string.
Returns binary string suitable for use as HMAC key."
  (let* ((k-date (restclient-sigv4-hmac-sha256
                  (concat "AWS4" secret-key) date))
         (k-region (restclient-sigv4-hmac-sha256 k-date region))
         (k-service (restclient-sigv4-hmac-sha256 k-region service))
         (k-signing (restclient-sigv4-hmac-sha256 k-service "aws4_request")))
    k-signing))

;;; Request Signing

(defun restclient-sigv4--parse-url (url)
  "Parse URL into components.
Returns a plist (:host :path :query-params).
QUERY-PARAMS is a list of (name . value) pairs."
  (condition-case _err
      (let* ((parsed (url-generic-parse-url url))
             (host (url-host parsed))
             (path (or (url-filename parsed) "/"))
             ;; url-filename includes query string, split it
             (path-and-query (split-string path "?" t))
             (clean-path (or (car path-and-query) "/"))
             (query-string (cadr path-and-query))
             (query-params
              (when query-string
                (mapcar (lambda (pair)
                          (let ((kv (split-string pair "=" t)))
                            (cons (or (car kv) "")
                                  (or (cadr kv) ""))))
                        (split-string query-string "&" t)))))
        ;; Ensure path starts with /
        (when (or (string= clean-path "") (not (string-prefix-p "/" clean-path)))
          (setq clean-path (concat "/" clean-path)))
        (list :host host
              :path clean-path
              :query-params query-params))
    (error
     (error "restclient-sigv4: signer: malformed URI: %s" url))))

(defun restclient-sigv4--format-timestamp (time)
  "Format TIME as SigV4 timestamp string YYYYMMDDTHHMMSSZ.
TIME is a time value as returned by `current-time', or nil for now."
  (format-time-string "%Y%m%dT%H%M%SZ" (or time (current-time)) t))

(defun restclient-sigv4--format-datestamp (time)
  "Format TIME as SigV4 datestamp string YYYYMMDD.
TIME is a time value as returned by `current-time', or nil for now."
  (format-time-string "%Y%m%d" (or time (current-time)) t))

(defun restclient-sigv4-sign-request (method url headers body credential region service timestamp)
  "Sign a request and return updated headers alist with auth headers added.
METHOD: HTTP method string.
URL: full request URL.
HEADERS: alist of (name . value) pairs.
BODY: request body string or nil.
CREDENTIAL: plist (:access-key-id K :secret-access-key S :session-token T).
REGION: AWS region string.
SERVICE: AWS service string.
TIMESTAMP: UTC time as (HIGH LOW USEC PSEC) or nil for current time."
  (let* ((access-key-id (plist-get credential :access-key-id))
         (secret-access-key (plist-get credential :secret-access-key))
         (session-token (plist-get credential :session-token))
         ;; Compute timestamps
         (amz-date (restclient-sigv4--format-timestamp timestamp))
         (datestamp (restclient-sigv4--format-datestamp timestamp))
         ;; Compute body hash
         (body-hash (restclient-sigv4-sha256 (or body "")))
         ;; Parse URL
         (url-parts (restclient-sigv4--parse-url url))
         (host (plist-get url-parts :host))
         (path (plist-get url-parts :path))
         (query-params (plist-get url-parts :query-params))
         ;; URI-encode the path (each segment individually)
         (canonical-path
          (let ((segments (split-string path "/" t)))
            (if segments
                (concat "/"
                        (mapconcat (lambda (seg)
                                     (restclient-sigv4-uri-encode seg t))
                                   segments
                                   "/"))
              "/")))
         ;; Build headers for signing: add required AWS headers
         (signing-headers headers)
         ;; Add x-amz-date
         (_ (setq signing-headers
                  (cons (cons "x-amz-date" amz-date)
                        signing-headers)))
         ;; Add x-amz-content-sha256
         (_ (setq signing-headers
                  (cons (cons "x-amz-content-sha256" body-hash)
                        signing-headers)))
         ;; Add host if not already present
         (_ (unless (cl-find "host" signing-headers
                             :key #'car
                             :test (lambda (a b) (string= (downcase a) (downcase b))))
              (setq signing-headers
                    (cons (cons "host" host)
                          signing-headers))))
         ;; Add x-amz-security-token if session token present
         (_ (when session-token
              (setq signing-headers
                    (cons (cons "x-amz-security-token" session-token)
                          signing-headers))))
         ;; Build canonical request
         (creq (restclient-sigv4-canonical-request
                method canonical-path query-params signing-headers body-hash))
         ;; Serialize and hash canonical request
         (creq-string (restclient-sigv4-serialize-canonical-request creq))
         (creq-hash (restclient-sigv4-sha256 creq-string))
         ;; Build credential scope
         (credential-scope (concat datestamp "/" region "/" service "/aws4_request"))
         ;; Build string-to-sign
         (string-to-sign (concat "AWS4-HMAC-SHA256" "\n"
                                 amz-date "\n"
                                 credential-scope "\n"
                                 creq-hash))
         ;; Derive signing key
         (signing-key (restclient-sigv4-derive-signing-key
                       secret-access-key datestamp region service))
         ;; Compute signature
         (signature (encode-hex-string
                     (restclient-sigv4-hmac-sha256 signing-key string-to-sign)))
         ;; Get signed headers from canonical request
         (signed-headers (plist-get creq :signed-headers))
         ;; Build Authorization header
         (auth-header (concat "AWS4-HMAC-SHA256 "
                              "Credential=" access-key-id "/" credential-scope ", "
                              "SignedHeaders=" signed-headers ", "
                              "Signature=" signature)))
    ;; Return updated headers with auth headers added
    ;; Start with original headers, add AWS headers
    (let ((result headers))
      ;; Add x-amz-date
      (setq result (cons (cons "x-amz-date" amz-date) result))
      ;; Add x-amz-content-sha256
      (setq result (cons (cons "x-amz-content-sha256" body-hash) result))
      ;; Add x-amz-security-token if present
      (when session-token
        (setq result (cons (cons "x-amz-security-token" session-token) result)))
      ;; Add Authorization header
      (setq result (cons (cons "Authorization" auth-header) result))
      result)))

(provide 'restclient-sigv4-signer)
;;; restclient-sigv4-signer.el ends here
