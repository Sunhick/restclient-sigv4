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

(provide 'restclient-sigv4)
;;; restclient-sigv4.el ends here
