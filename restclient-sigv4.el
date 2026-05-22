;;; restclient-sigv4.el --- AWS SigV4 signing for restclient.el  -*- lexical-binding: t; -*-

;; Copyright (C) 2026  Sunil Murthy
;; Author: Sunil Murthy
;; Version: 0.1.0
;; Package-Requires: ((emacs "27.1") (restclient "0"))
;; Keywords: comm, tools
;; URL: https://github.com/Sunhick/restclient-sigv4

;; This file is not part of GNU Emacs.

;;; Commentary:

;; Main entry point and integration layer for restclient-sigv4.
;; This package adds AWS Signature Version 4 (SigV4) request signing
;; to restclient.el via the `restclient-http-do-hook' mechanism.

;;; Code:

(require 'restclient)
(require 'restclient-sigv4-signer)
(require 'restclient-sigv4-credentials)

(provide 'restclient-sigv4)
;;; restclient-sigv4.el ends here
