;;; restclient-sigv4.el --- AWS SigV4 signing for restclient.el  -*- lexical-binding: t; -*-

;; Copyright (C) 2026  Sunil Murthy
;; Author: Sunil Murthy
;; Version: 0.1.0
;; Package-Requires: ((emacs "27.1") (restclient "0"))
;; Keywords: comm, tools
;; URL: https://github.com/Sunhick/restclient-sigv4

;; This file is not part of GNU Emacs.

;; This program is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <https://www.gnu.org/licenses/>.

;;; Commentary:

;; This package adds AWS Signature Version 4 (SigV4) request signing
;; to restclient.el via the `restclient-http-do-hook' mechanism.
;;
;; To use, add an X-Sigv4 header to your restclient request with
;; region and service parameters:
;;
;;   X-Sigv4: region=us-east-1 service=execute-api
;;
;; Credentials are resolved from environment variables (AWS_ACCESS_KEY_ID,
;; AWS_SECRET_ACCESS_KEY) or the AWS credentials file (~/.aws/credentials).

;;; Code:

(require 'restclient)
(require 'restclient-sigv4-signer)
(require 'restclient-sigv4-credentials)

;;; Customization

(defgroup restclient-sigv4 nil
  "AWS SigV4 signing for restclient.el."
  :group 'restclient
  :prefix "restclient-sigv4-")

(defcustom restclient-sigv4-default-region nil
  "Default AWS region.  Used when :sigv4 directive omits region."
  :type '(choice (const :tag "None" nil) string)
  :group 'restclient-sigv4
  :safe #'stringp)

(defcustom restclient-sigv4-credentials-file "~/.aws/credentials"
  "Path to AWS credentials file."
  :type 'string
  :group 'restclient-sigv4
  :safe #'stringp)

;;; Directive parsing

(defconst restclient-sigv4--allowed-params '("region" "service" "profile")
  "Allowed parameter keys for the :sigv4 directive.")

(defun restclient-sigv4-parse-directive (value)
  "Parse VALUE string into plist (:region R :service S :profile P).
VALUE is a space-separated list of key=value pairs.
Signals error for invalid parameter keys or empty values."
  (let ((parts (split-string value nil t))
        result)
    (dolist (part parts)
      (unless (string-match "\\`\\([^=]+\\)=\\(.*\\)\\'" part)
        (error "restclient-sigv4: directive: malformed parameter '%s'" part))
      (let ((key (match-string 1 part))
            (val (match-string 2 part)))
        (unless (member key restclient-sigv4--allowed-params)
          (error "restclient-sigv4: directive: invalid parameter '%s' (allowed: region, service, profile)" key))
        (when (string-empty-p val)
          (error "restclient-sigv4: directive: empty value for parameter '%s'" key))
        (setq result (plist-put result (intern (concat ":" key)) val))))
    result))

;;; Hook function

;; Declare `url' as a special variable so it is dynamically accessible
;; from `restclient-http-do-hook'.  In restclient.el (which uses
;; lexical-binding), `url' is a function parameter of `restclient-http-do'.
;; By declaring it special here, Emacs treats all bindings of `url' as
;; dynamic, making it visible to hook functions.
;; The lack of a package prefix is intentional — this references
;; restclient.el's own parameter name.
(defvar url) ;; noqa: prefix

(defun restclient-sigv4-hook ()
  "Sign the current request if X-Sigv4 header is present.
This function is intended to be added to `restclient-http-do-hook'.
It inspects `url-request-extra-headers' for an \"X-Sigv4\" entry.
When present, it removes the header, parses the directive, resolves
credentials, signs the request, and updates `url-request-extra-headers'
with the signed headers.  When absent, it does nothing."
  (let ((sigv4-entry (assoc "X-Sigv4" url-request-extra-headers)))
    (when sigv4-entry
      ;; Remove X-Sigv4 header from the headers alist
      (setq url-request-extra-headers
            (assoc-delete-all "X-Sigv4" url-request-extra-headers))
      ;; Parse directive parameters
      (let* ((directive (restclient-sigv4-parse-directive (cdr sigv4-entry)))
             (region (or (plist-get directive :region)
                         restclient-sigv4-default-region))
             (service (plist-get directive :service))
             (profile (plist-get directive :profile)))
        ;; Validate required parameters
        (unless region
          (error "restclient-sigv4: directive: missing required parameter 'region'"))
        (unless service
          (error "restclient-sigv4: directive: missing required parameter 'service'"))
        ;; Resolve credentials
        (let ((credential (restclient-sigv4-resolve-credentials profile)))
          ;; Sign the request and update headers
          (setq url-request-extra-headers
                (restclient-sigv4-sign-request
                 url-request-method
                 url
                 url-request-extra-headers
                 url-request-data
                 credential
                 region
                 service
                 nil)))))))

;;; Enable/Disable

(defun restclient-sigv4-enable ()
  "Enable SigV4 signing for restclient.el requests.
Adds `restclient-sigv4-hook' to `restclient-http-do-hook'."
  (interactive)
  (add-hook 'restclient-http-do-hook #'restclient-sigv4-hook))

(defun restclient-sigv4-disable ()
  "Disable SigV4 signing for restclient.el requests.
Removes `restclient-sigv4-hook' from `restclient-http-do-hook'."
  (interactive)
  (remove-hook 'restclient-http-do-hook #'restclient-sigv4-hook))

;; Auto-enable on load
(restclient-sigv4-enable)

(provide 'restclient-sigv4)
;;; restclient-sigv4.el ends here
