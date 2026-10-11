<h1 align="center">Filament</h1>

<p align="center">
  <strong>A single-file USB tool for Linux</strong><br>
  TUI • CLI • Write • Format • Wipe
</p>

<p align="center">
  No build system. No headers. No surprises.
</p>

<p align="center">
  <a href="#what-it-is">What it is</a>
  •
  <a href="#features">Features</a>
  •
  <a href="#quick-start">Quick start</a>
  •
  <a href="#cli">CLI</a>
  •
  <a href="#safety">Safety</a>
  •
  <a href="#requirements">Requirements</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-v1.1.0-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/license-CLEAR_v1-yellow?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/targets-Linux-informational?style=flat-square" alt="Targets">
</p>

---

## What it is

Filament writes ISO images to USB drives, formats drives as
FAT32/exFAT, and wipes drives. One C file. TUI or CLI. libc and
ncurses, nothing else.

It refuses to touch mounted devices or the disk holding `/`. It makes
you type the device name before anything destructive. It tells you
when the kernel is still buffering writes instead of inventing a
speed number.

## Features

- Write ISO images: raw write, configurable block size, progress,
  speed, ETA
- Verify after write: byte-for-byte, mandatory
- SHA-256 hashing: optional, off by default, source and target
- Format: FAT32, VFAT, exFAT
- Partition tables: MBR, GPT
- Quick wipe: first 1 MB
- Full zero: entire device
- Safety checks: refuses mounted devices and system disks
- Device name confirmation for anything destructive
- Filesystem detection: FAT32, exFAT, NTFS; partition table type
- Multi-device listing of removable USB devices
- File browser with hidden-file toggle
- Full CLI mode
- SIGINT handling
- Honest progress: `buffering...` until writes block, then real
  device speed

## Quick start

```sh
gcc -std=c99 -Wall -Wextra -pedantic -O2 -o filament filament.c -lncurses
sudo ./filament
```

## TUI

### Main menu

| Key | Action |
|------|--------|
| `1` | Write ISO to USB |
| `2` | Format USB |
| `3` | Wipe/zero USB |
| `4` / `Q` | Quit |

### Device selection

| Key | Action |
|------|--------|
| `↑` / `↓` | Navigate |
| `Enter` | Select |
| `Q` | Back |

### File browser

| Key | Action |
|------|--------|
| `↑` / `↓` | Navigate |
| `Enter` | Open / select |
| `Backspace` | Parent directory |
| `H` | Toggle hidden files |
| `Q` | Cancel |

### Confirm write

| Key | Action |
|------|--------|
| `V` | Toggle SHA-256 output |
| `Enter` | Confirm (asks for device name) |
| `Backspace` | Back |
| `Q` | Cancel |

### Format options

| Key | Action |
|------|--------|
| `F` | Cycle filesystem (FAT32 / VFAT / exFAT) |
| `T` | Toggle partition table (MBR / GPT) |
| `L` | Set volume label |
| `Enter` | Start |
| `Backspace` | Back |

### Wipe/zero

| Key | Action |
|------|--------|
| `Q` | Quick wipe (first 1 MB) |
| `F` | Full zero |
| Other | Cancel |

Destructive operations require typing the device name (`sdb`).

## CLI

```sh
filament --version
filament --help
filament --list

sudo filament --write /dev/sdb image.iso
sudo filament --write /dev/sdb image.iso --sha256
sudo filament --write /dev/sdb image.iso --no-verify
sudo filament --write /dev/sdb image.iso --dry-run
sudo filament --write /dev/sdb image.iso --unmount
sudo filament --write /dev/sdb image.iso --block-size=1048576

sudo filament --wipe /dev/sdb
sudo filament --zero /dev/sdb

sudo filament --format /dev/sdb --fat32
sudo filament --format /dev/sdb --exfat --gpt --label=MYUSB
```

Block size: 4096 to 67108864 bytes.

## Slow USB sticks

USB sticks lie. The kernel absorbs writes into page cache at hundreds
of MB/s, then dribbles them to flash at whatever the flash can do.

- Speed shows `buffering...` while the kernel absorbs. No fake
  number.
- Once writes block, speed switches to `(writing)` and shows real
  device speed.
- Verify reads back from the device. Always honest.
- After the write pass, `Syncing to Device` while the kernel flushes.
  Slow devices can take a minute. Not a hang. **Do not remove the
  device.**

Total wall time is unchanged. Filament just tells you where it went.

## Filesystems

| Filesystem | Write ISO | Format | Notes |
|------------|-----------|--------|-------|
| FAT32 | ✓ | ✓ | Universal, 4 GB file limit |
| VFAT | — | ✓ | FAT32 with long names |
| exFAT | — | ✓ | Large files, modern systems |
| NTFS | — | — | Detected, not formattable |

## External tools

Formatting shells out. Nothing else does.

| Operation | Requires |
|-----------|----------|
| Format FAT32 / VFAT | `mkfs.vfat` (dosfstools) |
| Format exFAT | `mkfs.exfat` (exfatprogs) or `mkexfatfs` (exfat-utils) |

Write, verify, wipe, zero, list, and the TUI do not touch external
tools. Missing formatters means formatting fails; everything else
works.

## Safety

- Mounted device check: refuses anything mounted
- System disk check: refuses devices containing `/` or `/boot`
- Device name confirmation: type `sdb` before anything destructive
- Dry run: `--dry-run` shows what would happen
- Clear identification: model, serial, size, filesystem, partition
  table

## Requirements

`ncurses` for the TUI.

```sh
# Artix / Arch
sudo pacman -S ncurses

# Debian / Ubuntu
sudo apt install libncurses-dev

# Fedora
sudo dnf install ncurses-devel

# Void
sudo xbps-install ncurses-devel
```

Formatting also needs:

```sh
# Artix / Arch
sudo pacman -S dosfstools exfatprogs

# Debian / Ubuntu
sudo apt install dosfstools exfatprogs

# Fedora
sudo dnf install dosfstools exfatprogs

# Void
sudo xbps-install dosfstools exfatprogs
```

## Project layout

```text
FILAMENT/
├── filament.c
├── LICENSE
└── README.md
```

# Why Filament Exists

I'll be dead honest here. I fucking hate balenaEtcher, Rufus isn't portable to Linux, and `dd` reminds me of drinking 2 liters of red wine with not so great outcomes.

Filament is simple, safe, fast, and works. It does one thing well, among a few other things.

## Contributing

Single file. Minimal dependencies.

## License

[CLEAR v1](LICENSE) © [realvolk](https://github.com/realvolk) 2026.