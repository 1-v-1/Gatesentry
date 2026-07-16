include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-gatesentry
PKG_VERSION:=1.23.0
PKG_RELEASE:=1

PKG_LICENSE:=MIT
PKG_MAINTAINER:=GateSentry contributors

LUCI_TITLE:=LuCI support for GateSentry
LUCI_DEPENDS:=+gatesentry
LUCI_PKGARCH:=all

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-gatesentry
	SECTION:=luci
	CATEGORY:=LuCI
	SUBMENU:=3. Applications
	TITLE:=GateSentry LuCI application
	PKGARCH:=all
	DEPENDS:=+gatesentry +luci-base
endef

define Package/luci-app-gatesentry/description
	LuCI web interface for GateSentry runtime parameters. Filter rules,
	users, blocklists, HTTPS interception and the certificate authority
	remain in the full web admin on port 10786 of the running service.
endef

define Package/luci-app-gatesentry/install
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller
	$(INSTALL_DATA) ./files/usr/lib/lua/luci/controller/gatesentry.lua \
		$(1)/usr/lib/lua/luci/controller/gatesentry.lua

	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/model/cbi/gatesentry
	$(INSTALL_DATA) ./files/usr/lib/lua/luci/model/cbi/gatesentry/basic.lua \
		$(1)/usr/lib/lua/luci/model/cbi/gatesentry/basic.lua

	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/view/gatesentry
	$(INSTALL_DATA) ./files/usr/lib/lua/luci/view/gatesentry/status.htm \
		$(1)/usr/lib/lua/luci/view/gatesentry/status.htm

	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d
	$(INSTALL_DATA) ./files/usr/share/rpcd/acl.d/luci-app-gatesentry.json \
		$(1)/usr/share/rpcd/acl.d/luci-app-gatesentry.json
endef

$(eval $(call BuildPackage,luci-app-gatesentry))