;;; restclient-sigv4a-pbt.el --- Property-based tests for restclient-sigv4a  -*- lexical-binding: t; -*-

;; Copyright (C) 2026  Sunil Murthy

;; This file is not part of GNU Emacs.

;;; Commentary:

;; Property-based tests using propcheck for restclient-sigv4a.
;; Feature: sigv4a-support

;;; Code:

(require 'ert)
(require 'propcheck)
(require 'restclient-sigv4-signer)

;;; Generators

(defun restclient-sigv4a-pbt--generate-http-method (_name)
  "Generate a random HTTP method string."
  (let* ((methods ["GET" "POST" "PUT" "DELETE" "PATCH" "HEAD" "OPTIONS"])
         (idx (mod (propcheck--draw-byte propcheck-seed) (length methods))))
    (aref methods idx)))

(defun restclient-sigv4a-pbt--generate-path-segment (_name)
  "Generate a random URL path segment."
  (let ((chars nil)
        (len (+ 1 (mod (propcheck--draw-byte propcheck-seed) 12))))
    (dotimes (_ len)
      (let* ((byte (propcheck--draw-byte propcheck-seed))
             (charset "abcdefghijklmnopqrstuvwxyz0123456789-_.")
             (char (aref charset (mod byte (length charset)))))
        (push char chars)))
    (concat (nreverse chars))))

(defun restclient-sigv4a-pbt--generate-url (_name)
  "Generate a random valid HTTPS URL."
  (let* ((hosts ["example.com" "api.example.com" "s3.amazonaws.com"
                 "execute-api.us-east-1.amazonaws.com" "sqs.us-west-2.amazonaws.com"])
         (host (aref hosts (mod (propcheck--draw-byte propcheck-seed) (length hosts))))
         (num-segments (+ 1 (mod (propcheck--draw-byte propcheck-seed) 4)))
         (segments nil))
    (dotimes (_ num-segments)
      (push (restclient-sigv4a-pbt--generate-path-segment nil) segments))
    (concat "https://" host "/" (mapconcat #'identity (nreverse segments) "/"))))

(defun restclient-sigv4a-pbt--generate-header-name (_name)
  "Generate a random header name."
  (let* ((names ["content-type" "accept" "x-custom-header" "cache-control"
                 "x-request-id" "user-agent" "content-length" "x-trace-id"])
         (idx (mod (propcheck--draw-byte propcheck-seed) (length names))))
    (aref names idx)))

(defun restclient-sigv4a-pbt--generate-header-value (_name)
  "Generate a random header value."
  (let ((chars nil)
        (len (+ 1 (mod (propcheck--draw-byte propcheck-seed) 20))))
    (dotimes (_ len)
      (let* ((byte (propcheck--draw-byte propcheck-seed))
             (charset "abcdefghijklmnopqrstuvwxyz0123456789 /;=+-")
             (char (aref charset (mod byte (length charset)))))
        (push char chars)))
    (string-trim (concat (nreverse chars)))))

(defun restclient-sigv4a-pbt--generate-headers (_name)
  "Generate a random list of request headers (0-4 headers)."
  (let ((result nil)
        (count (mod (propcheck--draw-byte propcheck-seed) 5)))
    (dotimes (_ count)
      (let ((name (restclient-sigv4a-pbt--generate-header-name nil))
            (value (restclient-sigv4a-pbt--generate-header-value nil)))
        ;; Avoid duplicate header names
        (unless (assoc name result)
          (push (cons name value) result))))
    (nreverse result)))

(defun restclient-sigv4a-pbt--generate-body (_name)
  "Generate a random request body (possibly nil)."
  (let ((choice (mod (propcheck--draw-byte propcheck-seed) 3)))
    (cond
     ((= choice 0) nil)
     ((= choice 1) "")
     (t
      (let ((chars nil)
            (len (+ 1 (mod (propcheck--draw-byte propcheck-seed) 50))))
        (dotimes (_ len)
          (let* ((byte (propcheck--draw-byte propcheck-seed))
                 (charset "abcdefghijklmnopqrstuvwxyz0123456789 {}\":,[]")
                 (char (aref charset (mod byte (length charset)))))
            (push char chars)))
        (concat (nreverse chars)))))))

(defun restclient-sigv4a-pbt--generate-access-key-id (_name)
  "Generate a random AWS access key ID."
  (let ((chars nil))
    (dotimes (_ 20)
      (let* ((byte (propcheck--draw-byte propcheck-seed))
             (charset "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
             (char (aref charset (mod byte (length charset)))))
        (push char chars)))
    (concat "AKIA" (substring (concat (nreverse chars)) 0 16))))

(defun restclient-sigv4a-pbt--generate-secret-access-key (_name)
  "Generate a random AWS secret access key."
  (let ((chars nil))
    (dotimes (_ 40)
      (let* ((byte (propcheck--draw-byte propcheck-seed))
             (charset "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/")
             (char (aref charset (mod byte (length charset)))))
        (push char chars)))
    (concat (nreverse chars))))

(defun restclient-sigv4a-pbt--generate-session-token (_name)
  "Generate a random session token or nil."
  (let ((has-token (mod (propcheck--draw-byte propcheck-seed) 2)))
    (if (= has-token 0)
        nil
      (let ((chars nil))
        (dotimes (_ 60)
          (let* ((byte (propcheck--draw-byte propcheck-seed))
                 (charset "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=")
                 (char (aref charset (mod byte (length charset)))))
            (push char chars)))
        (concat (nreverse chars))))))

(defun restclient-sigv4a-pbt--generate-region (_name)
  "Generate a random AWS region string."
  (let* ((regions ["us-east-1" "us-west-2" "eu-west-1" "ap-southeast-1"
                   "ca-central-1" "sa-east-1" "eu-central-1" "ap-northeast-1"])
         (idx (mod (propcheck--draw-byte propcheck-seed) (length regions))))
    (aref regions idx)))

(defun restclient-sigv4a-pbt--generate-service (_name)
  "Generate a random AWS service string."
  (let* ((services ["s3" "execute-api" "sqs" "sns" "dynamodb" "lambda"
                    "sts" "iam" "ec2" "kinesis"])
         (idx (mod (propcheck--draw-byte propcheck-seed) (length services))))
    (aref services idx)))

(defun restclient-sigv4a-pbt--generate-timestamp (_name)
  "Generate a random timestamp as Emacs time value."
  ;; Generate a timestamp between 2020-01-01 and 2030-01-01
  (let* ((base-time (encode-time 0 0 0 1 1 2020 t))
         (base-seconds (float-time base-time))
         ;; Add random offset up to ~10 years in seconds
         (offset-high (mod (propcheck--draw-byte propcheck-seed) 255))
         (offset-low (propcheck--draw-byte propcheck-seed))
         ;; Scale to reasonable range (up to ~315M seconds = ~10 years)
         (offset (* (+ (* offset-high 256) offset-low) 4800))
         (target-seconds (+ base-seconds offset)))
    (seconds-to-time target-seconds)))

;;; Property 13: Backward compatibility — SigV4 signing is unaffected
;; Feature: sigv4a-support, Property 13: Backward compatibility — SigV4 signing is unaffected
;;
;; For any valid SigV4 request parameters (method, URL, headers, body,
;; credentials, region, service, timestamp), the standard SigV4 signer
;; SHALL produce byte-for-byte identical Authorization headers and output
;; headers regardless of whether the SigV4A signer module is loaded, and
;; regardless of whether the OpenSSL CLI is available in the environment.
;;
;; Validates: Requirements 8.4, 9.1, 9.2, 9.3

(propcheck-deftest restclient-sigv4a-pbt-backward-compat-sigv4a-loaded ()
  "Property 13: Backward compatibility — SigV4 signing is unaffected.
Verify SigV4 produces identical output whether or not SigV4A module is loaded.

Feature: sigv4a-support, Property 13: Backward compatibility — SigV4 signing is unaffected
Validates: Requirements 8.4, 9.1, 9.2, 9.3"
  :num-tests 100
  (let* ((method (restclient-sigv4a-pbt--generate-http-method nil))
         (url (restclient-sigv4a-pbt--generate-url nil))
         (headers (restclient-sigv4a-pbt--generate-headers nil))
         (body (restclient-sigv4a-pbt--generate-body nil))
         (access-key-id (restclient-sigv4a-pbt--generate-access-key-id nil))
         (secret-access-key (restclient-sigv4a-pbt--generate-secret-access-key nil))
         (session-token (restclient-sigv4a-pbt--generate-session-token nil))
         (region (restclient-sigv4a-pbt--generate-region nil))
         (service (restclient-sigv4a-pbt--generate-service nil))
         (timestamp (restclient-sigv4a-pbt--generate-timestamp nil))
         (credential (list :access-key-id access-key-id
                           :secret-access-key secret-access-key
                           :session-token session-token)))
    ;; Sign WITHOUT SigV4A module loaded (unload if present)
    (let ((sigv4a-was-loaded (featurep 'restclient-sigv4a-signer)))
      (when sigv4a-was-loaded
        (unload-feature 'restclient-sigv4a-signer t))
      (let ((result-without-sigv4a
             (restclient-sigv4-sign-request method url headers body
                                           credential region service timestamp)))
        ;; Now load SigV4A module and sign again
        (require 'restclient-sigv4a-signer)
        (let ((result-with-sigv4a
               (restclient-sigv4-sign-request method url headers body
                                             credential region service timestamp)))
          ;; Restore original state
          (unless sigv4a-was-loaded
            (unload-feature 'restclient-sigv4a-signer t))
          ;; Assert byte-for-byte identical output
          (propcheck-should (equal result-without-sigv4a result-with-sigv4a)))))))

(propcheck-deftest restclient-sigv4a-pbt-backward-compat-no-openssl ()
  "Property 13: Backward compatibility — SigV4 works when openssl is not in PATH.
Verify SigV4 signing completes successfully even when openssl is unavailable.

Feature: sigv4a-support, Property 13: Backward compatibility — SigV4 signing is unaffected
Validates: Requirements 8.4, 9.1, 9.2, 9.3"
  :num-tests 100
  (let* ((method (restclient-sigv4a-pbt--generate-http-method nil))
         (url (restclient-sigv4a-pbt--generate-url nil))
         (headers (restclient-sigv4a-pbt--generate-headers nil))
         (body (restclient-sigv4a-pbt--generate-body nil))
         (access-key-id (restclient-sigv4a-pbt--generate-access-key-id nil))
         (secret-access-key (restclient-sigv4a-pbt--generate-secret-access-key nil))
         (session-token (restclient-sigv4a-pbt--generate-session-token nil))
         (region (restclient-sigv4a-pbt--generate-region nil))
         (service (restclient-sigv4a-pbt--generate-service nil))
         (timestamp (restclient-sigv4a-pbt--generate-timestamp nil))
         (credential (list :access-key-id access-key-id
                           :secret-access-key secret-access-key
                           :session-token session-token)))
    ;; Sign with openssl available (normal case)
    (let ((result-with-openssl
           (restclient-sigv4-sign-request method url headers body
                                         credential region service timestamp)))
      ;; Sign with openssl NOT available (mock executable-find to return nil for openssl)
      (let ((result-without-openssl
             (cl-letf (((symbol-function 'executable-find)
                        (lambda (cmd)
                          (unless (string= cmd "openssl")
                            (executable-find cmd)))))
               (restclient-sigv4-sign-request method url headers body
                                             credential region service timestamp))))
        ;; Assert byte-for-byte identical output
        (propcheck-should (equal result-with-openssl result-without-openssl))))))

(provide 'restclient-sigv4a-pbt)
;;; restclient-sigv4a-pbt.el ends here
