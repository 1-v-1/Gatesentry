include $(TOPDIR)/rules.mk

PKG_NAME:=gatesentry
PKG_VERSION:=1.23.0
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=skip

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

PKG_SOURCE:=https://github.com/1-v-1/Gatesentry/releases/download/v$(PKG_VERSION)/$(GS_BIN)
PKG_HASH:=skip

include $(INCLUDE_DIR)/package.mk

# Download the matching prebuilt binary into $(PKG_BUILD_DIR) before install.
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(WGET) -q -O $(PKG_BUILD_DIR)/gatesentry-bin $(PKG_SOURCE)
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
	DEPENDS:=+libpthread
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
endef

define Package/gatesentry/postinst
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] || {
	mkdir -p /var/lib/gatesentry/gatesentry/filterfiles
	chown -R gatesentry:gatesentry /var/lib/gatesentry

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

$(eval $(call BuildPackage,gatesentry))