# SPDX-License-Identifier: GPL-2.0-only
include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=octeon-offload
PKG_RELEASE:=6
PKG_LICENSE:=GPL-2.0-only

include $(INCLUDE_DIR)/package.mk

define KernelPackage/octeon-offload
  SUBMENU:=Network Support
  TITLE:=Octeon packet forwarding offload
  DEPENDS:=@TARGET_octeon +kmod-nft-offload
  FILES:=$(PKG_BUILD_DIR)/octeon-offload.ko
  AUTOLOAD:=$(call AutoProbe,octeon-offload)
endef

define KernelPackage/octeon-offload/description
  Forwards established flows in the Octeon ethernet driver's receive path,
  fed by nf_flowtable hardware offload (fw4: flow_offloading_hw). Needs the
  octeon target's forwarding offload driver hooks.
endef

define Build/Compile
	+$(KERNEL_MAKE) M=$(PKG_BUILD_DIR) modules
endef

# Package/kmod-*, not KernelPackage/*: kernel.mk doesn't forward postinst.
# Runs after default_postinst, which on a running system has loaded the module
# (kmodloader) and applied the uci-defaults. A module loaded while fw4's
# flowtable exists is bound to only one of its ports (the kernel's replay keeps
# one record per flowtable), and the uci change needs a reload anyway: reload
# fw4 so every port binds. An upgrade keeps the old module running until reboot.
define Package/kmod-octeon-offload/postinst
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ] && [ -x /etc/init.d/firewall ]; then
	/etc/init.d/firewall reload >/dev/null 2>&1
fi
endef

define KernelPackage/octeon-offload/install
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/octeon-offload.defaults $(1)/etc/uci-defaults/90-octeon-offload
endef

$(eval $(call KernelPackage,octeon-offload))
