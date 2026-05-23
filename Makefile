.PHONY: all test pbt clean byte-compile lint deps distclean test-sigv4a pbt-sigv4a test-all pbt-all

EMACS ?= emacs
BATCH := $(EMACS) -Q --batch

SRC := restclient-sigv4.el restclient-sigv4-signer.el restclient-sigv4-credentials.el
SRC_SIGV4A := restclient-sigv4a-signer.el
TEST := test/restclient-sigv4-test.el
TEST_SIGV4A := test/restclient-sigv4a-test.el
PBT := test/restclient-sigv4-pbt.el
PBT_SIGV4A := test/restclient-sigv4a-pbt.el
DEPS_DIR := .deps
PROPCHECK_DIR := $(DEPS_DIR)/propcheck

PACKAGE_INIT := --eval '(setq package-user-dir (expand-file-name "$(DEPS_DIR)"))' \
	--eval '(package-initialize)'

all: deps byte-compile test

deps: $(DEPS_DIR)/.installed

$(DEPS_DIR)/.installed:
	mkdir -p $(DEPS_DIR)
	$(BATCH) --eval '(progn \
	  (setq package-user-dir (expand-file-name "$(DEPS_DIR)")) \
	  (setq package-archives (quote (("melpa" . "https://melpa.org/packages/") ("gnu" . "https://elpa.gnu.org/packages/")))) \
	  (package-initialize) \
	  (package-refresh-contents) \
	  (package-install (quote restclient)) \
	  (package-install (quote dash)))'
	git clone --depth 1 https://github.com/Wilfred/propcheck.git $(PROPCHECK_DIR) 2>/dev/null || true
	touch $(DEPS_DIR)/.installed

byte-compile: $(SRC) $(SRC_SIGV4A) $(DEPS_DIR)/.installed
	$(BATCH) $(PACKAGE_INIT) -L . -f batch-byte-compile $(SRC) $(SRC_SIGV4A)

test: $(SRC) $(TEST) $(DEPS_DIR)/.installed
	$(BATCH) $(PACKAGE_INIT) -L . -l ert -l $(TEST) -f ert-run-tests-batch-and-exit

pbt: $(SRC) $(PBT) $(DEPS_DIR)/.installed
	$(BATCH) $(PACKAGE_INIT) -L . -L $(PROPCHECK_DIR) -l ert -l $(PBT) -f ert-run-tests-batch-and-exit

test-sigv4a: $(SRC) $(SRC_SIGV4A) $(TEST_SIGV4A) $(DEPS_DIR)/.installed
	$(BATCH) $(PACKAGE_INIT) -L . -l ert -l $(TEST_SIGV4A) -f ert-run-tests-batch-and-exit

pbt-sigv4a: $(SRC) $(SRC_SIGV4A) $(PBT_SIGV4A) $(DEPS_DIR)/.installed
	$(BATCH) $(PACKAGE_INIT) -L . -L $(PROPCHECK_DIR) -l ert -l $(PBT_SIGV4A) -f ert-run-tests-batch-and-exit

test-all: test test-sigv4a

pbt-all: pbt pbt-sigv4a

lint: $(SRC) $(DEPS_DIR)/.installed
	$(BATCH) $(PACKAGE_INIT) -L . --eval '(setq byte-compile-error-on-warn t)' -f batch-byte-compile $(SRC)

clean:
	rm -f *.elc test/*.elc

distclean: clean
	rm -rf $(DEPS_DIR)
