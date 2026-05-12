APP=centralssh
KEYSCAN_TOOL=cssh-keyscan
PROFILE?=release
TARGET_TRIPLE?=

PREFIX?=/usr/local
SBINDIR?=$(PREFIX)/sbin
BINDIR?=$(PREFIX)/bin
SYSCONFDIR?=/etc/centralssh
LOCALSTATEDIR?=/var
LOGDIR?=$(LOCALSTATEDIR)/log/centralssh
RUNDIR?=$(LOCALSTATEDIR)/run

FREEBSD_RC_DIR?=$(PREFIX)/etc/rc.d
SYSTEMD_UNIT_DIR?=/etc/systemd/system

CARGO?=cargo
INSTALL?=install

BIN_DIR:=$(if $(TARGET_TRIPLE),$(CARGO_TARGET_DIR)/$(TARGET_TRIPLE)/$(PROFILE),$(CARGO_TARGET_DIR)/$(PROFILE))
APP_BIN:=$(BIN_DIR)/$(APP)

.PHONY: all build clean install uninstall \
	install-bin install-tools install-layout install-config install-service \
	install-service-freebsd install-service-linux check-build

all: build

build:
	$(CARGO) build --profile $(PROFILE) $(if $(TARGET_TRIPLE),--target $(TARGET_TRIPLE),)

clean:
	$(CARGO) clean

install: check-build install-bin install-tools install-layout install-config install-service
	@echo "Installed $(APP)."
	@echo "FreeBSD start: service centralssh start"
	@echo "systemd start: systemctl start centralssh"

check-build:
	@if [ ! -x "$(APP_BIN)" ]; then \
		echo "Missing $(APP_BIN). Run 'make PROFILE=$(PROFILE) $(if $(TARGET_TRIPLE),TARGET_TRIPLE=$(TARGET_TRIPLE),)' first."; \
		exit 1; \
	fi

install-bin:
	$(INSTALL) -d $(DESTDIR)$(SBINDIR)
	$(INSTALL) -m 0755 $(APP_BIN) $(DESTDIR)$(SBINDIR)/$(APP)

install-tools:
	$(INSTALL) -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 tools/$(KEYSCAN_TOOL) $(DESTDIR)$(BINDIR)/$(KEYSCAN_TOOL)

install-layout:
	$(INSTALL) -d -m 0700 $(DESTDIR)$(SYSCONFDIR)/users
	$(INSTALL) -d -m 0700 $(DESTDIR)$(LOGDIR)
	@if [ ! -f $(DESTDIR)$(SYSCONFDIR)/known_hosts ]; then \
		$(INSTALL) -m 0600 /dev/null $(DESTDIR)$(SYSCONFDIR)/known_hosts; \
	fi
	@if [ ! -f $(DESTDIR)$(LOGDIR)/audit.jsonl ]; then \
		$(INSTALL) -m 0600 /dev/null $(DESTDIR)$(LOGDIR)/audit.jsonl; \
	fi

install-config:
	$(INSTALL) -d -m 0700 $(DESTDIR)$(SYSCONFDIR)
	@if [ ! -f $(DESTDIR)$(SYSCONFDIR)/config.toml ]; then \
		$(INSTALL) -m 0600 examples/config.toml $(DESTDIR)$(SYSCONFDIR)/config.toml; \
	fi
	@if [ ! -f $(DESTDIR)$(SYSCONFDIR)/servers.toml ]; then \
		$(INSTALL) -m 0600 examples/servers.toml $(DESTDIR)$(SYSCONFDIR)/servers.toml; \
	fi

install-service:
	@if [ "$$(uname -s)" = "FreeBSD" ]; then \
		$(MAKE) install-service-freebsd; \
	else \
		$(MAKE) install-service-linux; \
	fi

install-service-freebsd:
	$(INSTALL) -d $(DESTDIR)$(FREEBSD_RC_DIR)
	$(INSTALL) -m 0555 packaging/freebsd/centralssh $(DESTDIR)$(FREEBSD_RC_DIR)/centralssh
	@echo "Add to rc.conf: centralssh_enable=\"YES\""

install-service-linux:
	$(INSTALL) -d $(DESTDIR)$(SYSTEMD_UNIT_DIR)
	$(INSTALL) -m 0644 packaging/systemd/centralssh.service $(DESTDIR)$(SYSTEMD_UNIT_DIR)/centralssh.service
	@if [ -z "$(DESTDIR)" ] && command -v systemctl >/dev/null 2>&1; then \
		systemctl daemon-reload; \
		systemctl enable centralssh.service >/dev/null 2>&1 || true; \
	fi

uninstall:
	rm -f $(DESTDIR)$(SBINDIR)/$(APP)
	rm -f $(DESTDIR)$(BINDIR)/$(KEYSCAN_TOOL)
	rm -f $(DESTDIR)$(FREEBSD_RC_DIR)/centralssh
	rm -f $(DESTDIR)$(SYSTEMD_UNIT_DIR)/centralssh.service
