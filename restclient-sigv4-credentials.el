;;; restclient-sigv4-credentials.el --- Credential resolution  -*- lexical-binding: t; -*-

;; Copyright (C) 2026  Sunil Murthy

;; This file is not part of GNU Emacs.

;;; Commentary:

;; Resolves AWS credentials from environment variables and the AWS
;; credentials file.  Supports profile selection via directive parameter,
;; AWS_PROFILE environment variable, or the "default" profile.

;;; Code:

(defun restclient-sigv4-parse-ini-file (file)
  "Parse INI-format FILE into alist of (section . ((key . value) ...)).
Signal error if FILE does not exist or is malformed."
  (unless (file-exists-p file)
    (error "restclient-sigv4: credentials: file not found: %s" file))
  (let ((sections '())
        (current-section nil)
        (current-pairs '()))
    (with-temp-buffer
      (insert-file-contents file)
      (goto-char (point-min))
      (while (not (eobp))
        (let ((line (buffer-substring-no-properties
                     (line-beginning-position) (line-end-position))))
          (cond
           ;; Blank lines
           ((string-match-p "\\`[ \t]*\\'" line)
            nil)
           ;; Comment lines (starting with # or ;)
           ((string-match-p "\\`[ \t]*[#;]" line)
            nil)
           ;; Section header [section-name]
           ((string-match "\\`[ \t]*\\[\\([^]]+\\)\\][ \t]*\\'" line)
            ;; Save previous section if any
            (when current-section
              (push (cons current-section (nreverse current-pairs)) sections))
            (setq current-section (match-string 1 line))
            (setq current-pairs '()))
           ;; Key = value pair
           ((string-match "\\`[ \t]*\\([^=]+?\\)[ \t]*=[ \t]*\\(.*?\\)[ \t]*\\'" line)
            (let ((key (match-string 1 line))
                  (value (match-string 2 line)))
              (push (cons key value) current-pairs)))
           ;; Malformed line
           (t
            (error "restclient-sigv4: credentials: malformed INI file: %s" file))))
        (forward-line 1)))
    ;; Save last section
    (when current-section
      (push (cons current-section (nreverse current-pairs)) sections))
    (nreverse sections)))

(defun restclient-sigv4-read-credentials-file (file profile)
  "Read credentials for PROFILE from FILE.
Returns plist (:access-key-id :secret-access-key :session-token) on success.
Signals error if FILE does not exist, PROFILE is not found, or required
fields are missing."
  (let* ((sections (restclient-sigv4-parse-ini-file file))
         (section (assoc profile sections)))
    (unless section
      (let ((available (mapcar #'car sections)))
        (error "restclient-sigv4: credentials: profile '%s' not found in %s (available: %s)"
               profile file (string-join available ", "))))
    (let* ((pairs (cdr section))
           (access-key (cdr (assoc "aws_access_key_id" pairs)))
           (secret-key (cdr (assoc "aws_secret_access_key" pairs)))
           (session-token (cdr (assoc "aws_session_token" pairs))))
      (when (or (null access-key) (string-empty-p access-key))
        (error "restclient-sigv4: credentials: profile '%s' missing required field '%s'"
               profile "aws_access_key_id"))
      (when (or (null secret-key) (string-empty-p secret-key))
        (error "restclient-sigv4: credentials: profile '%s' missing required field '%s'"
               profile "aws_secret_access_key"))
      (list :access-key-id access-key
            :secret-access-key secret-key
            :session-token (if (and session-token (not (string-empty-p session-token)))
                               session-token
                             nil)))))

(provide 'restclient-sigv4-credentials)
;;; restclient-sigv4-credentials.el ends here
