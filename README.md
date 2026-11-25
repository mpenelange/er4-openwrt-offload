# er4-openwrt-offload

Hardware flow offload for stock OpenWrt on the Ubiquiti EdgeRouter 4.

A small patch to the Octeon ethernet driver plus a kmod that forwards flows handed to it by
nf_flowtable (fw4 `flow_offloading_hw`). The kernel's vermagic stays the same as the official
release, so official packages and kmods still install.

Offloads IPv4/IPv6 TCP and UDP between the ethernet ports, IPv4 NAT, and single 802.1Q tags.
PPPoE, IPv6 NAT, tunnels and so on stay in the software path.

## Build

```sh
git clone --branch v25.12.6 https://github.com/openwrt/openwrt.git
cd openwrt
cp ../er4-openwrt-offload/patches/octeon-6.12/*.patch target/linux/octeon/patches-6.12/
cp -r ../er4-openwrt-offload/package/kernel/octeon-offload package/kernel/
./scripts/feeds update -a && ./scripts/feeds install -a
curl -fLo .config https://downloads.openwrt.org/releases/25.12.6/targets/octeon/generic/config.buildinfo
echo CONFIG_PACKAGE_kmod-octeon-offload=y >> .config
make defconfig && make -j$(nproc) IGNORE_ERRORS=m
```

Install the sysupgrade image as usual. Counters are in `/proc/octeon_offload`.

GPL-2.0.
