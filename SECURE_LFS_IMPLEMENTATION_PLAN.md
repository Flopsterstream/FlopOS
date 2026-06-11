# Secure Privacy-Focused LFS Implementation Plan

This document outlines the comprehensive plan and implementation details for building a highly secure, privacy-respecting Linux distribution from scratch, based on the principles of Linux From Scratch (LFS).

## 1. System Architecture Overview
- **Base System:** LFS modified for binary packaging.
- **Package Manager:** `apk-tools` with a custom build system (like `abuild`).
- **Init System:** OpenRC.
- **Kernel:** Upstream Linux with strict hardening configurations.
- **Boot Process:** LUKS FDE with a custom, minimal initramfs.
- **Mandatory Access Control:** AppArmor.
- **GUI:** Wayland compositor (Labwc).
- **Networking:** Strict default-deny `nftables`, netns-based per-app Tor/VPN routing, local DNS sinkhole.

## 2. Base System and Package Management

Instead of the traditional LFS approach where source code is compiled and installed directly to the root filesystem, this distribution uses a custom build system inspired by Alpine Linux's `abuild`.

### Custom Build Environment
1. **LFS Cross-Toolchain:** The initial step follows the standard LFS process to build a cross-compiler toolchain in an isolated `/mnt/lfs` environment.
2. **Bootstrapping `apk-tools`:** Once the temporary toolchain is built, we cross-compile `apk-tools` (statically linked) to manage the nascent system.
3. **Packaging Recipes:** Every software component from the standard LFS book (e.g., glibc/musl, binutils, coreutils) is packaged using custom build scripts (e.g., `APKBUILD` files).
4. **Creating the Repository:** The build system outputs `.apk` files to a local repository structure, generates cryptographic signatures for the packages, and builds the `APKINDEX`.
5. **System Installation:** The base system is installed onto the target drive by running `apk add --root /mnt/target <base-packages>`.

## 3. Storage and Boot Process (LUKS + Initramfs)

### Disk Layout
To minimize attack surface and secure data at rest, Full Disk Encryption (FDE) is employed.
- `/boot`: Unencrypted partition containing the kernel, initramfs, and bootloader (e.g., GRUB or systemd-boot). (Optionally, use Secure Boot to verify the kernel/initramfs).
- `/`: LUKS2 encrypted partition containing the root filesystem.

### Custom Minimal Initramfs
Instead of relying on complex generators like `dracut` or `mkinitcpio`, a custom, minimal initramfs is written from scratch. This reduces the codebase executed as root during the boot process.

**Initramfs Implementation Details:**
1. **Directory Structure:** Create a minimal rootfs structure (`/bin`, `/dev`, `/etc`, `/lib`, `/mnt/root`, `/proc`, `/sys`).
2. **Dependencies:** Compile statically linked versions of `busybox` (for sh, mount, mknod) and `cryptsetup` (for LUKS). Include necessary kernel modules (`dm_crypt`, `aes`, `sha256`, keyboard drivers).
3. **The `init` Script:**
```sh
#!/bin/sh
# 1. Mount virtual filesystems
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev

# 2. Load necessary modules
modprobe dm_crypt
modprobe ext4 # or btrfs, depending on choice
# Keyboard modules (e.g., usbhid)

# 3. Prompt for LUKS password and unlock
cryptsetup luksOpen /dev/sda2 cryptroot

# 4. Mount the decrypted root filesystem
mount /dev/mapper/cryptroot /mnt/root

# 5. Clean up
umount /proc
umount /sys
umount /dev

# 6. Switch root and hand off to OpenRC
exec switch_root /mnt/root /sbin/init
```

## 4. Kernel Hardening and Sandboxing (AppArmor)

### Kernel Hardening (Upstream)
The Linux kernel is configured to reduce attack surface and mitigate exploitation vectors. No out-of-tree patches are used, relying strictly on upstream security options.
Key configurations (`make menuconfig` / `make xconfig`):
- `CONFIG_SECURITY_LOCKDOWN_LSM=y` and `CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY=y`
- `CONFIG_STRICT_KERNEL_RWX=y` (Enforce strict page permissions)
- `CONFIG_STRICT_MODULE_RWX=y`
- `CONFIG_PAGE_TABLE_ISOLATION=y` (PTI against Meltdown)
- `CONFIG_RANDOMIZE_BASE=y` and `CONFIG_RANDOMIZE_MEMORY=y` (KASLR)
- `CONFIG_HARDENED_USERCOPY=y`
- `CONFIG_FORTIFY_SOURCE=y`
- `CONFIG_SLAB_FREELIST_RANDOM=y` and `CONFIG_SLAB_FREELIST_HARDENED=y`
- `CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y` and `CONFIG_INIT_ON_FREE_DEFAULT_ON=y` (Wipe memory allocations)
- `CONFIG_USER_NS=n` (Disable user namespaces by default unless strictly required, to mitigate local privilege escalations).
- Disable unused file systems, legacy binary formats (e.g., `a.out`), and debugging interfaces (e.g., `CONFIG_KALLSYMS`, `CONFIG_DEBUG_FS`).

### Sandboxing (AppArmor)
AppArmor provides Mandatory Access Control (MAC) to restrict applications' capabilities, even if they run as root.
1. **Kernel Configuration:** Enable `CONFIG_SECURITY_APPARMOR=y` and set it as the default security module.
2. **Userspace Tools:** Compile and package `apparmor-utils` and `apparmor-profiles`.
3. **Implementation Strategy:**
   - Run OpenRC with an AppArmor init script that loads profiles before other services start.
   - Start in `complain` mode to log violations without breaking functionality, then refine profiles.
   - Switch all critical network-facing applications (e.g., LibreWolf, dnscrypt-proxy) and the compositor (Labwc) to `enforce` mode.
   - Employ strict profiles: restrict file system access to necessary directories (e.g., `~/Downloads` for the browser), deny execution of unknown binaries, and limit network access to specific ports and protocols.

## 5. Network Architecture, Privacy, and Routing

### Strict Firewall (`nftables`)
A default-deny firewall is implemented to block all unsolicited inbound traffic and tightly control outbound traffic.
- **Inbound:** `policy drop`. No daemons listen on external interfaces by default.
- **Outbound:** `policy drop`. Only explicitly permitted traffic (e.g., DNS to the local sinkhole, HTTP/S proxy traffic, VPN tunnels) is allowed.

### Local DNS Sinkhole
To enforce "no phone home" policies and block telemetry:
1. Install and configure `dnscrypt-proxy` or a hardened local `unbound` instance.
2. Configure `/etc/resolv.conf` to point exclusively to `127.0.0.1`.
3. Integrate blocklists (e.g., StevenBlack hosts) directly into the DNS resolver configuration.
4. Route all system DNS queries through the sinkhole, dropping any outbound UDP/TCP port 53 traffic that doesn't originate from the local resolver.

### Leak-Proof Per-Application Tor/VPN Routing
To allow specific applications to route traffic exclusively through Tor or a VPN without any chance of falling back to the clearnet, we utilize Linux Network Namespaces (`netns`).

**Implementation Strategy:**
1. **Create the Namespace:**
   ```sh
   ip netns add anon_net
   ip link add veth0 type veth peer name veth1
   ip link set veth1 netns anon_net
   ```
2. **Configure Routing & Firewall in the Namespace:**
   - Inside `anon_net`, set up the routing table to force all traffic through a `tun` interface established by OpenVPN/WireGuard or a local proxy port managed by Tor.
   - Apply specific `nftables` rules *inside* `anon_net` to drop everything except traffic destined for the VPN endpoint or Tor daemon. If the VPN connection drops, the routing table has no default gateway to the physical interface, creating a foolproof kill-switch.
3. **The Wrapper Script:**
   Create a wrapper script (e.g., `run_anon`) to launch applications inside this isolated environment:
   ```sh
   #!/bin/sh
   # run_anon - Wrapper to run an application in the isolated netns
   APP=$1
   shift
   # Use 'ip netns exec' or 'firejail --netns' combined with a non-root user
   sudo -u restricted_user ip netns exec anon_net "$APP" "$@"
   ```
4. **System-wide Toggle:**
   A master OpenRC script is provided to dynamically bring up or tear down the `anon_net` namespace and its associated VPN/Tor tunnels, allowing the user to toggle the privacy network on or off at will.

## 6. Graphical Interface (Wayland/Labwc) and Applications

### Minimal GUI Environment
To avoid the large attack surface and legacy cruft of X11, the system uses Wayland exclusively.
1. **Compositor:** `labwc` is chosen for its minimal footprint, lack of built-in bloat, and Openbox-like configuration.
2. **Wayland Support:** Ensure all compiled packages (e.g., Mesa, SDL2, GTK, Qt) are built strictly with Wayland support and *without* X11 or Xwayland support.
3. **Display Manager:** Instead of a complex display manager like GDM or SDDM, use a minimal console-based login (e.g., `greetd` with `tuigreet`) or launch the compositor directly from the TTY after login.

### Privacy-Centric Applications
1. **Web Browser:** Compile and package `LibreWolf` (a hardened fork of Firefox) from source. Configure default policies to disable WebGL, WebRTC, telemetry, and strictly enforce HTTPS.
2. **Terminal:** `foot` or `alacritty` for a fast, minimal, Wayland-native terminal emulator.
3. **Isolation:** Wrap all GUI applications using AppArmor profiles restricting access to only essential config files and the `Downloads` directory. For network-facing apps, they can be launched using the `run_anon` wrapper script defined in Section 5 to enforce traffic routing.

## 7. Security Operations and Maintenance

### Minimizing Attack Surface
- By default, no network listening services (like `sshd`, `cupsd`, or `avahi`) are installed or running.
- Bluetooth and Wi-Fi modules are blacklisted in `/etc/modprobe.d/` unless explicitly required and enabled by the user.
- Compilers and development headers are stripped from the final system image to hinder local privilege escalation exploit compilation.

### Updates and Audits
- The custom `apk` repository will be maintained on an isolated build server. Updates are downloaded securely over HTTPS (or Tor).
- System administration relies heavily on `apk-tools` for atomic upgrades and cryptographically verifying package signatures.
- Implement routine file integrity monitoring (e.g., AIDE) to audit the filesystem for unauthorized changes to critical binaries.
