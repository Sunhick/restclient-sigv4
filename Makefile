.PHONY: all test pbt clean byte-compile lint

EMACS ?= emacs
BATCH := $(EMACS) -Q --batch

SRC := restclient-sigv4.el restclient-sigv4-signer.el restclient-sigv4-credentials.el
TEST := test/restclient-sigv4-test.el
PBT := test/restclient-sigv4-pbt.el

all: byte-compile test

byte-compile: $(SRC)
	$(BATCH) -L . -f batch-byte-compile $(SRC)

test: $(SRC) $(TEST)
	$(BATCH) -L . -l ert -l $(TEST) -f ert-run-tests-batch-and-exit

pbt: $(SRC) $(PBT)
	$(BATCH) -L . -l ert -l $(PBT) -f ert-run-tests-batch-and-exit

lint: $(SRC)
	$(BATCH) -L . --eval '(setq byte-compile-error-on-warn t)' -f batch-byte-compile $(SRC)

clean:
	rm -f *.elc test/*.elc
