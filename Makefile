.PHONY: all test pbt clean byte-compile lint deps

EMACS ?= emacs
BATCH := $(EMACS) -Q --batch

SRC := restclient-sigv4.el restclient-sigv4-signer.el restclient-sigv4-credentials.el
TEST := test/restclient-sigv4-test.el
PBT := test/restclient-sigv4-pbt.el
DEPS_DIR := .deps
PROPCHECK_DIR := $(DEPS_DIR)/propcheck

all: byte-compile test

deps: $(DEPS_DIR)/.installed

$(DEPS_DIR)/.installed:
	mkdir -p $(DEPS_DIR)
	$(BATCH) --eval '(progn \
	  (setq package-user-dir (expand-file-name "$(DEPS_DIR)")) \
	  (setq package-archives (quote (("melpa" . "https://melpa.org/packages/") ("gnu" . "https://elpa.gnu.org/packages/")))) \
	  (package-initialize) \
	  (package-refresh-contents) \
	  (package-install (quote dash)))'
	git clone --depth 1 https://github.com/Wilfred/propcheck.git $(PROPCHECK_DIR) 2>/dev/null || true
	touch $(DEPS_DIR)/.installed

byte-compile: $(SRC)
	$(BATCH) -L . -f batch-byte-compile $(SRC)

test: $(SRC) $(TEST)
	$(BATCH) -L . -l ert -l $(TEST) -f ert-run-tests-batch-and-exit

pbt: $(SRC) $(PBT) $(DEPS_DIR)/.installed
	$(BATCH) --eval '(setq package-user-dir (expand-file-name "$(DEPS_DIR)"))' \
	  --eval '(package-initialize)' \
	  -L . -L $(PROPCHECK_DIR) -l ert -l $(PBT) -f ert-run-tests-batch-and-exit

lint: $(SRC)
	$(BATCH) -L . --eval '(setq byte-compile-error-on-warn t)' -f batch-byte-compile $(SRC)

clean:
	rm -f *.elc test/*.elc

distclean: clean
	rm -rf $(DEPS_DIR)
