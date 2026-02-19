APP=centralssh

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

.PHONY: all build clean install uninstall \
	install-bin install-layout install-config install-service \
	install-service-freebsd install-service-linux check-build

all: build

build:
	$(CARGO) build --release

clean:
	$(CARGO) clean

install: check-build install-bin install-layout install-config install-service
	@echo "Installed $(APP)."
	@echo "FreeBSD start: service centralssh start"
	@echo "systemd start: systemctl start centralssh"

check-build:
	@if [ ! -x target/release/$(APP) ]; then \
		echo "Missing target/release/$(APP). Run 'make' first."; \
		exit 1; \
	fi

install-bin:
	$(INSTALL) -d $(DESTDIR)$(SBINDIR)
	$(INSTALL) -m 0755 target/release/$(APP) $(DESTDIR)$(SBINDIR)/$(APP)

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
	@if [ ! -f $(DESTDIR)$(SYSCONFDIR)/config.json ]; then \
		$(INSTALL) -m 0600 examples/config.json $(DESTDIR)$(SYSCONFDIR)/config.json; \
	fi
	@if [ ! -f $(DESTDIR)$(SYSCONFDIR)/servers.json ]; then \
		$(INSTALL) -m 0600 examples/servers.json $(DESTDIR)$(SYSCONFDIR)/servers.json; \
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
	rm -f $(DESTDIR)$(FREEBSD_RC_DIR)/centralssh
	rm -f $(DESTDIR)$(SYSTEMD_UNIT_DIR)/centralssh.service
