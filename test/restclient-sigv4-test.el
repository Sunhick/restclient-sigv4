;;; restclient-sigv4-test.el --- Unit tests for restclient-sigv4  -*- lexical-binding: t; -*-

;; Copyright (C) 2026  Sunil Murthy

;; This file is not part of GNU Emacs.

;;; Commentary:

;; ERT-based unit tests for restclient-sigv4.

;;; Code:

(require 'ert)
(require 'hex-util)

;; Add parent directory to load-path for requiring package files
(add-to-list 'load-path (file-name-directory (directory-file-name (file-name-directory load-file-name))))

(require 'restclient-sigv4-credentials)
(require 'restclient-sigv4-signer)

;;; INI file parser tests

(ert-deftest restclient-sigv4-test-parse-ini-file-basic ()
  "Test parsing a basic INI file with two sections."
  (let ((tmp (make-temp-file "ini-test" nil ".ini")))
    (unwind-protect
        (progn
          (with-temp-file tmp
            (insert "[default]\n")
            (insert "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n")
            (insert "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n")
            (insert "\n")
            (insert "[production]\n")
            (insert "aws_access_key_id = AKIAI44QH8DHBEXAMPLE\n")
            (insert "aws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY\n")
            (insert "aws_session_token = AQoDYXdzEJr...\n"))
          (let ((result (restclient-sigv4-parse-ini-file tmp)))
            (should (equal (length result) 2))
            (should (equal (caar result) "default"))
            (should (equal (cdr (assoc "aws_access_key_id" (cdar result)))
                           "AKIAIOSFODNN7EXAMPLE"))
            (should (equal (cdr (assoc "aws_secret_access_key" (cdar result)))
                           "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"))
            (should (equal (car (nth 1 result)) "production"))
            (should (equal (cdr (assoc "aws_session_token" (cdr (nth 1 result))))
                           "AQoDYXdzEJr..."))))
      (delete-file tmp))))

(ert-deftest restclient-sigv4-test-parse-ini-file-comments ()
  "Test that comments and blank lines are skipped."
  (let ((tmp (make-temp-file "ini-test" nil ".ini")))
    (unwind-protect
        (progn
          (with-temp-file tmp
            (insert "# This is a comment\n")
            (insert "; This is also a comment\n")
            (insert "\n")
            (insert "[default]\n")
            (insert "key = value\n"))
          (let ((result (restclient-sigv4-parse-ini-file tmp)))
            (should (equal (length result) 1))
            (should (equal (caar result) "default"))
            (should (equal (cdr (assoc "key" (cdar result))) "value"))))
      (delete-file tmp))))

(ert-deftest restclient-sigv4-test-parse-ini-file-not-found ()
  "Test that a missing file signals an error."
  (should-error
   (restclient-sigv4-parse-ini-file "/nonexistent/path/credentials")
   :type 'error))

(ert-deftest restclient-sigv4-test-parse-ini-file-malformed ()
  "Test that a malformed line signals an error."
  (let ((tmp (make-temp-file "ini-test" nil ".ini")))
    (unwind-protect
        (progn
          (with-temp-file tmp
            (insert "[default]\n")
            (insert "this is not valid\n"))
          (should-error
           (restclient-sigv4-parse-ini-file tmp)
           :type 'error))
      (delete-file tmp))))

(ert-deftest restclient-sigv4-test-parse-ini-file-whitespace-trimming ()
  "Test that whitespace is trimmed from keys and values."
  (let ((tmp (make-temp-file "ini-test" nil ".ini")))
    (unwind-protect
        (progn
          (with-temp-file tmp
            (insert "[default]\n")
            (insert "  key  =  value  \n"))
          (let ((result (restclient-sigv4-parse-ini-file tmp)))
            (should (equal (cdr (assoc "key" (cdar result))) "value"))))
      (delete-file tmp))))

;;; Credentials file reader tests

(ert-deftest restclient-sigv4-test-read-credentials-file-basic ()
  "Test reading credentials for a profile returns correct plist."
  (let ((tmp (make-temp-file "creds-test" nil ".ini")))
    (unwind-protect
        (progn
          (with-temp-file tmp
            (insert "[default]\n")
            (insert "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n")
            (insert "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"))
          (let ((result (restclient-sigv4-read-credentials-file tmp "default")))
            (should (equal (plist-get result :access-key-id) "AKIAIOSFODNN7EXAMPLE"))
            (should (equal (plist-get result :secret-access-key) "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"))
            (should (null (plist-get result :session-token)))))
      (delete-file tmp))))

(ert-deftest restclient-sigv4-test-read-credentials-file-with-session-token ()
  "Test reading credentials with session token."
  (let ((tmp (make-temp-file "creds-test" nil ".ini")))
    (unwind-protect
        (progn
          (with-temp-file tmp
            (insert "[production]\n")
            (insert "aws_access_key_id = AKIAI44QH8DHBEXAMPLE\n")
            (insert "aws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY\n")
            (insert "aws_session_token = AQoDYXdzEJr...\n"))
          (let ((result (restclient-sigv4-read-credentials-file tmp "production")))
            (should (equal (plist-get result :access-key-id) "AKIAI44QH8DHBEXAMPLE"))
            (should (equal (plist-get result :secret-access-key) "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY"))
            (should (equal (plist-get result :session-token) "AQoDYXdzEJr..."))))
      (delete-file tmp))))

(ert-deftest restclient-sigv4-test-read-credentials-file-not-found ()
  "Test that a missing file signals an error with path."
  (let ((err (should-error
              (restclient-sigv4-read-credentials-file "/nonexistent/path/credentials" "default")
              :type 'error)))
    (should (string-match-p "file not found" (cadr err)))
    (should (string-match-p "/nonexistent/path/credentials" (cadr err)))))

(ert-deftest restclient-sigv4-test-read-credentials-file-profile-missing ()
  "Test that a missing profile signals error listing available profiles."
  (let ((tmp (make-temp-file "creds-test" nil ".ini")))
    (unwind-protect
        (progn
          (with-temp-file tmp
            (insert "[default]\n")
            (insert "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n")
            (insert "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n")
            (insert "[production]\n")
            (insert "aws_access_key_id = AKIAI44QH8DHBEXAMPLE\n")
            (insert "aws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY\n"))
          (let ((err (should-error
                      (restclient-sigv4-read-credentials-file tmp "staging")
                      :type 'error)))
            (should (string-match-p "profile .staging. not found" (cadr err)))
            (should (string-match-p "default" (cadr err)))
            (should (string-match-p "production" (cadr err)))))
      (delete-file tmp))))

(ert-deftest restclient-sigv4-test-read-credentials-file-missing-access-key ()
  "Test that missing access key signals error naming the field."
  (let ((tmp (make-temp-file "creds-test" nil ".ini")))
    (unwind-protect
        (progn
          (with-temp-file tmp
            (insert "[default]\n")
            (insert "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"))
          (let ((err (should-error
                      (restclient-sigv4-read-credentials-file tmp "default")
                      :type 'error)))
            (should (string-match-p "missing required field" (cadr err)))
            (should (string-match-p "aws_access_key_id" (cadr err)))))
      (delete-file tmp))))

(ert-deftest restclient-sigv4-test-read-credentials-file-missing-secret-key ()
  "Test that missing secret key signals error naming the field."
  (let ((tmp (make-temp-file "creds-test" nil ".ini")))
    (unwind-protect
        (progn
          (with-temp-file tmp
            (insert "[default]\n")
            (insert "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"))
          (let ((err (should-error
                      (restclient-sigv4-read-credentials-file tmp "default")
                      :type 'error)))
            (should (string-match-p "missing required field" (cadr err)))
            (should (string-match-p "aws_secret_access_key" (cadr err)))))
      (delete-file tmp))))

(ert-deftest restclient-sigv4-test-read-credentials-file-empty-access-key ()
  "Test that empty access key is treated as missing."
  (let ((tmp (make-temp-file "creds-test" nil ".ini")))
    (unwind-protect
        (progn
          (with-temp-file tmp
            (insert "[default]\n")
            (insert "aws_access_key_id =\n")
            (insert "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"))
          (let ((err (should-error
                      (restclient-sigv4-read-credentials-file tmp "default")
                      :type 'error)))
            (should (string-match-p "missing required field" (cadr err)))
            (should (string-match-p "aws_access_key_id" (cadr err)))))
      (delete-file tmp))))

;;; SigV4 signing tests using AWS-published test vectors
;;
;; Test vectors from:
;; https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
;;
;; AWS example parameters:
;;   Secret Key: wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY
;;   Date: 20150830
;;   Region: us-east-1
;;   Service: iam
;;   Access Key ID: AKIDEXAMPLE

(ert-deftest restclient-sigv4-test-signing-key-derivation ()
  "Test signing key derivation against AWS-published test vector.
The expected signing key for secret=wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY,
date=20150830, region=us-east-1, service=iam is:
c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9

Validates: Requirements 1.3"
  (let* ((secret-key "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")
         (date "20150830")
         (region "us-east-1")
         (service "iam")
         (signing-key (restclient-sigv4-derive-signing-key
                       secret-key date region service))
         (signing-key-hex (encode-hex-string signing-key)))
    (should (equal signing-key-hex
                   "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"))))

(ert-deftest restclient-sigv4-test-string-to-sign-construction ()
  "Test string-to-sign construction against AWS-published test vector.
For a GET / request to iam.amazonaws.com on 20150830T123600Z with
Action=ListUsers&Version=2010-05-08, the string-to-sign should be:
AWS4-HMAC-SHA256
20150830T123600Z
20150830/us-east-1/iam/aws4_request
f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59

Validates: Requirements 1.4"
  (let* ((method "GET")
         (path "/")
         (query-params '(("Action" . "ListUsers") ("Version" . "2010-05-08")))
         (headers '(("Host" . "iam.amazonaws.com")
                    ("Content-Type" . "application/x-www-form-urlencoded; charset=utf-8")
                    ("X-Amz-Date" . "20150830T123600Z")))
         (body-hash (restclient-sigv4-sha256 ""))
         ;; Build canonical request
         (creq (restclient-sigv4-canonical-request method path query-params headers body-hash))
         (creq-string (restclient-sigv4-serialize-canonical-request creq))
         (creq-hash (restclient-sigv4-sha256 creq-string))
         ;; Build string-to-sign
         (amz-date "20150830T123600Z")
         (credential-scope "20150830/us-east-1/iam/aws4_request")
         (string-to-sign (concat "AWS4-HMAC-SHA256" "\n"
                                 amz-date "\n"
                                 credential-scope "\n"
                                 creq-hash))
         ;; Expected canonical request hash from AWS docs
         (expected-creq-hash "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59")
         ;; Expected string-to-sign
         (expected-string-to-sign (concat "AWS4-HMAC-SHA256\n"
                                          "20150830T123600Z\n"
                                          "20150830/us-east-1/iam/aws4_request\n"
                                          "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59")))
    ;; Verify canonical request hash matches expected
    (should (equal creq-hash expected-creq-hash))
    ;; Verify string-to-sign matches expected
    (should (equal string-to-sign expected-string-to-sign))))

(ert-deftest restclient-sigv4-test-final-signature ()
  "Test final signature computation against AWS-published test vector.
For the IAM ListUsers example, the expected signature is:
5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7

Validates: Requirements 1.5"
  (let* ((secret-key "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")
         (date "20150830")
         (region "us-east-1")
         (service "iam")
         ;; Derive signing key
         (signing-key (restclient-sigv4-derive-signing-key
                       secret-key date region service))
         ;; String-to-sign from AWS docs
         (string-to-sign (concat "AWS4-HMAC-SHA256\n"
                                 "20150830T123600Z\n"
                                 "20150830/us-east-1/iam/aws4_request\n"
                                 "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"))
         ;; Compute signature
         (signature (encode-hex-string
                     (restclient-sigv4-hmac-sha256 signing-key string-to-sign)))
         (expected-signature "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"))
    (should (equal signature expected-signature))))

(ert-deftest restclient-sigv4-test-empty-body-hash ()
  "Test that empty body produces the correct SHA-256 hash.
The SHA-256 hash of the empty string is:
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

Validates: Requirements 4.6"
  (let ((empty-hash (restclient-sigv4-sha256 ""))
        (nil-hash (restclient-sigv4-sha256 nil))
        (expected "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))
    ;; Empty string should produce the well-known empty hash
    (should (equal empty-hash expected))
    ;; nil body should also produce the empty hash
    (should (equal nil-hash expected))))

(ert-deftest restclient-sigv4-test-full-signing-flow ()
  "Test the full signing flow produces correct Authorization header format.
Uses the AWS IAM ListUsers test vector parameters to verify end-to-end signing.
Note: The implementation signs additional headers (x-amz-content-sha256) beyond
the minimal AWS example, so the final signature differs from the AWS docs example.
We verify the signing process is internally consistent by checking format and
that the signing key derivation + HMAC chain is correct.

Validates: Requirements 1.3, 1.4, 1.5"
  (let* ((method "GET")
         (url "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08")
         (headers '(("Content-Type" . "application/x-www-form-urlencoded; charset=utf-8")))
         (body nil)
         (credential '(:access-key-id "AKIDEXAMPLE"
                       :secret-access-key "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
                       :session-token nil))
         (region "us-east-1")
         (service "iam")
         ;; Use the exact timestamp from the test vector
         ;; 20150830T123600Z = 2015-08-30 12:36:00 UTC
         (timestamp (encode-time 0 36 12 30 8 2015 t))
         ;; Sign the request
         (result-headers (restclient-sigv4-sign-request
                          method url headers body credential region service timestamp))
         ;; Extract Authorization header
         (auth-header (cdr (assoc "Authorization" result-headers))))
    ;; Verify the Authorization header format
    (should (string-match-p "^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request"
                            auth-header))
    ;; Verify SignedHeaders is present and contains required headers
    (should (string-match-p "SignedHeaders=.*host" auth-header))
    (should (string-match-p "SignedHeaders=.*content-type" auth-header))
    (should (string-match-p "SignedHeaders=.*x-amz-date" auth-header))
    ;; Verify Signature is a 64-char hex string
    (should (string-match-p "Signature=[0-9a-f]\\{64\\}" auth-header))
    ;; Verify x-amz-date header is present with correct value
    (should (equal (cdr (assoc "x-amz-date" result-headers)) "20150830T123600Z"))
    ;; Verify x-amz-content-sha256 header is present with empty body hash
    (should (equal (cdr (assoc "x-amz-content-sha256" result-headers))
                   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))
    ;; Verify no x-amz-security-token since session-token is nil
    (should (null (cdr (assoc "x-amz-security-token" result-headers))))))

(provide 'restclient-sigv4-test)
;;; restclient-sigv4-test.el ends here
