;;; restclient-sigv4-test.el --- Unit tests for restclient-sigv4  -*- lexical-binding: t; -*-

;; Copyright (C) 2026  Sunil Murthy

;; This file is not part of GNU Emacs.

;;; Commentary:

;; ERT-based unit tests for restclient-sigv4.

;;; Code:

(require 'ert)

;; Add parent directory to load-path for requiring package files
(add-to-list 'load-path (file-name-directory (directory-file-name (file-name-directory load-file-name))))

(require 'restclient-sigv4-credentials)

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

(provide 'restclient-sigv4-test)
;;; restclient-sigv4-test.el ends here
