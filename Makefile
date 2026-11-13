CC ?= gcc
CFLAGS ?= -fPIC -Wall -Wextra -O2
LDFLAGS ?= -shared -lpam
BUILD_DIR := build
PAM_SRC := src/pam/pam_facelock.c
PAM_SO := $(BUILD_DIR)/pam_facelock.so

.PHONY: all pam test clean install uninstall deb

all: pam

pam: $(PAM_SO)

$(PAM_SO): $(PAM_SRC)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(PAM_SRC) -o $(PAM_SO) $(LDFLAGS)

test: pam
	PYTHONPATH=src python3 -m unittest discover -s tests -v

install:
	sudo ./install.sh

uninstall:
	sudo ./uninstall.sh

deb: pam
	./scripts/build-deb.sh

clean:
	rm -rf $(BUILD_DIR) dist *.deb
	find . -name "__pycache__" -type d -exec rm -rf {} +
