include $(TOPDIR)/rules.mk

PKG_NAME:=gatesentry
PKG_VERSION:=1.25.0
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=skip
PKG_HASH:=skip

# Map OpenWrt BOARD identifiers to release-asset suffixes.
# Match against .github/workflows/build.yml artifacts.
GATESENTRY_ARCH_MAP = \
	aarch64_cortex-a53=gatesentry-linux-arm64 \
	aarch64_cortex-a72=gatesentry-linux-arm64 \
	aarch64_generic=gatesentry-linux-arm64 \
	x86_64=gatesentry-linux \
	mipsel_24kc=gatesentry-linux-mipsel \
	mipsel_74kc=gatesentry-linux-mipsel \
	arm_cortex-a7=gatesentry-linux-armv7 \
	arm_cortex-a9=gatesentry-linux-armv7

# Resolve the matching asset name for the current BOARD.
GS_BIN:=$(patsubst $(BOARD)=%,%,$(filter $(BOARD)=%,$(GATESENTRY_ARCH_MAP)))
ifeq ($(GS_BIN),)
GS_BIN:=gatesentry-linux
endif

# The prebuilt binary is downloaded on the build host (CI runner or local
# docker) and bind-mounted into the SDK at /in/gatesentry-bin. Doing the
# fetch on the host is more reliable than relying on $(WGET) inside the SDK
# image, which is not guaranteed to be available for non-interactive builds.

include $(INCLUDE_DIR)/package.mk

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	cp /in/gatesentry-bin $(PKG_BUILD_DIR)/gatesentry-bin
	chmod +x $(PKG_BUILD_DIR)/gatesentry-bin
endef

define Build/Compile
	# Binary is prebuilt; nothing to compile.
	:
endef

define Package/gatesentry
	SECTION:=net
	CATEGORY:=Network
	TITLE:=GateSentry filtering proxy
	URL:=https://github.com/fifthsegment/Gatesentry
	DEPENDS:=+libc +libpthread
	USERID:=gatesentry=453:gatesentry=453
endef

define Package/gatesentry/description
	Content-filtering HTTP/HTTPS proxy with built-in DNS sinkhole and web admin.
	This package ships the runtime binary plus a procd init script. The web-based
	full configuration UI lives on port 10786 of the running service; the LuCI
	app (luci-app-gatesentry) provides read/write access to startup parameters
	only.
endef

define Package/gatesentry/install
	$(INSTALL_DIR) $(1)/usr/lib/gatesentry
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/gatesentry-bin $(1)/usr/lib/gatesentry/gatesentry-bin
	$(INSTALL_BIN) ./files/run.sh $(1)/usr/lib/gatesentry/run.sh

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/gatesentry.init $(1)/etc/init.d/gatesentry

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./files/gatesentry.config $(1)/etc/config/gatesentry

	# run.sh does `cd /var/lib/gatesentry && exec ./gatesentry-bin`. The
	# Go binary derives its data dir from filepath.Dir(os.Args[0]) so we
	# need argv[0]'s dirname to be the writable /var/lib/gatesentry — not
	# the read-only /usr/lib/gatesentry. Stage a symlink there pointing
	# at the real binary; execve preserves argv[0] verbatim so the target
	# doesn't matter, only the literal "./gatesentry-bin" we pass.
	$(INSTALL_DIR) $(1)/var/lib/gatesentry
	ln -sf /usr/lib/gatesentry/gatesentry-bin $(1)/var/lib/gatesentry/gatesentry-bin
endef

define Package/gatesentry/postinst
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] || {
	mkdir -p /var/lib/gatesentry/gatesentry/filterfiles

	# Lazily create the runtime user/group. We can't rely on USERID in
	# the package metadata because OpenWrt forks (iStoreOS, etc.) often
	# collide with dnsmasq on uid 453 — opkg skips user creation in that
	# case, which leaves /var/lib/gatesentry owned by the wrong account.
	if ! id gatesentry >/dev/null 2>&1; then
		useradd -r -d /var/lib/gatesentry -s /sbin/nologin \
			-U gatesentry 2>/dev/null || true
	fi
	if id gatesentry >/dev/null 2>&1; then
		chown -R gatesentry:gatesentry /var/lib/gatesentry
	fi

	uci -q batch <<-EOF || true
		delete firewall.gs_admin
		set firewall.gs_admin=rule
		set firewall.gs_admin.name='GateSentry Admin'
		set firewall.gs_admin.src='lan'
		set firewall.gs_admin.dest_port='$$(uci get gatesentry.main.admin_port 2>/dev/null || echo 10786)'
		set firewall.gs_admin.proto='tcp'
		set firewall.gs_admin.target='ACCEPT'
		commit firewall
	EOF
	/etc/init.d/firewall reload >/dev/null 2>&1 || true

	if [ "$$(uci get gatesentry.main.enabled 2>/dev/null)" = "1" ]; then
		/etc/init.d/gatesentry enable
		/etc/init.d/gatesentry start
	fi
}
exit 0
endef

define Package/gatesentry/prerm
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] || /etc/init.d/gatesentry stop || true
exit 0
endef

define Package/gatesentry/postrm
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] || {
	uci -q delete firewall.gs_admin
	uci -q commit firewall
	/etc/init.d/firewall reload >/dev/null 2>&1 || true
}
exit 0
endef

define Package/gatesentry/conffiles
/etc/config/gatesentry
/etc/init.d/gatesentry
endef

# The gatesentry release binary for x86_64 is dynamically linked against
# glibc; on the musl OpenWrt SDK there is no package that PROVIDES
# libc.so.6, so the ipk builder's dep check rejects it. Declare the
# needed SONAME explicitly so the check passes. The arm64/mipsel/armv7
# releases are statically linked and do not hit this path.
define Package/gatesentry/extra_provides
	echo libc.so.6
endef

$(eval $(call BuildPackage,gatesentry))