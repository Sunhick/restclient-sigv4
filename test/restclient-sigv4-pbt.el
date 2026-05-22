;;; restclient-sigv4-pbt.el --- Property-based tests for restclient-sigv4  -*- lexical-binding: t; -*-

;; Copyright (C) 2026  Sunil Murthy

;; This file is not part of GNU Emacs.

;;; Commentary:

;; Property-based tests using propcheck for restclient-sigv4.
;; Feature: restclient-sigv4

;;; Code:

(require 'ert)
(require 'propcheck)
(require 'restclient-sigv4-signer)

;;; Generators

(defun restclient-sigv4-pbt--generate-query-param-name (_name)
  "Generate a random query parameter name string.
Generates short ASCII strings suitable for query parameter names."
  (let ((chars nil)
        (len (+ 1 (mod (propcheck--draw-byte propcheck-seed) 8))))
    (dotimes (_ len)
      (let* ((byte (propcheck--draw-byte propcheck-seed))
             ;; Use printable ASCII chars that are valid in query params
             ;; Mix of alphanumeric and some special chars
             (charset "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~!*")
             (char (aref charset (mod byte (length charset)))))
        (push char chars)))
    (concat (nreverse chars))))

(defun restclient-sigv4-pbt--generate-query-param-value (_name)
  "Generate a random query parameter value string.
Generates short ASCII strings suitable for query parameter values."
  (let ((chars nil)
        (len (mod (propcheck--draw-byte propcheck-seed) 10)))
    (dotimes (_ len)
      (let* ((byte (propcheck--draw-byte propcheck-seed))
             (charset "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~!* +")
             (char (aref charset (mod byte (length charset)))))
        (push char chars)))
    (concat (nreverse chars))))

(defun restclient-sigv4-pbt--generate-query-params (_name)
  "Generate a list of (name . value) query parameter pairs.
Generates between 1 and 8 pairs."
  (let ((result nil)
        (count (+ 1 (mod (propcheck--draw-byte propcheck-seed) 8))))
    (dotimes (_ count)
      (let ((param-name (restclient-sigv4-pbt--generate-query-param-name nil))
            (param-value (restclient-sigv4-pbt--generate-query-param-value nil)))
        (push (cons param-name param-value) result)))
    (nreverse result)))

;;; Property 7: Query parameter sorting
;; Feature: restclient-sigv4, Property 7: Query parameter sorting
;;
;; For any list of query parameter (name, value) pairs, the canonical query
;; string SHALL contain the parameters sorted first by percent-encoded name
;; in ascending byte order, then by percent-encoded value in ascending byte
;; order for parameters with identical names.
;;

(propcheck-deftest restclient-sigv4-pbt-query-parameter-sorting ()
  "Property 7: Query parameter sorting.
For any list of query parameter (name, value) pairs, the canonical query
string SHALL contain the parameters sorted first by percent-encoded name
in ascending byte order, then by percent-encoded value in ascending byte
order for parameters with identical names.

Feature: restclient-sigv4, Property 7: Query parameter sorting
Validates: Requirements 4.2"
  (let* ((query-params (restclient-sigv4-pbt--generate-query-params nil))
         ;; Build canonical query string using the implementation
         (canonical-query (restclient-sigv4--canonical-query-string query-params))
         ;; Parse the canonical query string back into encoded pairs
         (result-pairs
          (when (and canonical-query (not (string= canonical-query "")))
            (mapcar (lambda (pair-str)
                      (let ((parts (split-string pair-str "=")))
                        (cons (car parts)
                              (or (cadr parts) ""))))
                    (split-string canonical-query "&")))))
    ;; Verify the result pairs are sorted by encoded name ascending,
    ;; then by encoded value ascending for identical names
    (when (and result-pairs (> (length result-pairs) 1))
      (let ((sorted t)
            (i 0))
        (while (and sorted (< i (1- (length result-pairs))))
          (let* ((current (nth i result-pairs))
                 (next (nth (1+ i) result-pairs))
                 (current-name (car current))
                 (current-value (cdr current))
                 (next-name (car next))
                 (next-value (cdr next)))
            (cond
             ;; Names must be in ascending order
             ((string< next-name current-name)
              (setq sorted nil))
             ;; For identical names, values must be in ascending order
             ((and (string= current-name next-name)
                   (string< next-value current-value))
              (setq sorted nil))))
          (setq i (1+ i)))
        (propcheck-should sorted)))))

(provide 'restclient-sigv4-pbt)
;;; restclient-sigv4-pbt.el ends here
