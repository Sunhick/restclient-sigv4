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

(provide 'restclient-sigv4)
;;; restclient-sigv4.el ends here
