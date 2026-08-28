#!/usr/bin/env python3
"""Patch an ELF64 kernel module using CRCs and vermagic from donor modules."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path


def sections(data: bytes) -> dict[str, tuple[int, int]]:
    if data[:4] != b"\x7fELF" or data[4:6] != b"\x02\x01":
        raise ValueError("expected a little-endian ELF64 file")

    shoff = struct.unpack_from("<Q", data, 40)[0]
    shentsize = struct.unpack_from("<H", data, 58)[0]
    shnum = struct.unpack_from("<H", data, 60)[0]
    shstrndx = struct.unpack_from("<H", data, 62)[0]
    shstr_hdr = shoff + shstrndx * shentsize
    shstr_off = struct.unpack_from("<Q", data, shstr_hdr + 24)[0]

    result: dict[str, tuple[int, int]] = {}
    for index in range(shnum):
        header = shoff + index * shentsize
        name_index = struct.unpack_from("<I", data, header)[0]
        name_start = shstr_off + name_index
        name_end = data.index(0, name_start)
        name = data[name_start:name_end].decode("ascii")
        offset = struct.unpack_from("<Q", data, header + 24)[0]
        size = struct.unpack_from("<Q", data, header + 32)[0]
        result[name] = (offset, size)
    return result


def versions(data: bytes) -> dict[str, int]:
    offset, size = sections(data)["__versions"]
    if size % 64:
        raise ValueError("unexpected __versions entry size")
    result: dict[str, int] = {}
    for entry in range(offset, offset + size, 64):
        crc = struct.unpack_from("<Q", data, entry)[0]
        raw_name = data[entry + 8 : entry + 64].split(b"\0", 1)[0]
        result[raw_name.decode("ascii")] = crc
    return result


def patch_versions(data: bytearray, donor_crcs: dict[str, int]) -> list[str]:
    offset, size = sections(data)["__versions"]
    patched: list[str] = []
    for entry in range(offset, offset + size, 64):
        raw_name = data[entry + 8 : entry + 64].split(b"\0", 1)[0]
        name = raw_name.decode("ascii")
        if name in donor_crcs:
            old_crc = struct.unpack_from("<Q", data, entry)[0]
            new_crc = donor_crcs[name]
            if old_crc != new_crc:
                struct.pack_into("<Q", data, entry, new_crc)
                patched.append(f"{name}: 0x{old_crc:08x} -> 0x{new_crc:08x}")
    return patched


def patch_vermagic(data: bytearray, release: str) -> tuple[str, str]:
    offset, size = sections(data)[".modinfo"]
    raw = bytes(data[offset : offset + size])
    values = [value for value in raw.rstrip(b"\0").split(b"\0") if value]
    index = next(i for i, value in enumerate(values) if value.startswith(b"vermagic="))
    old = values[index].decode("ascii")
    suffix = old.split(" ", 1)[1]
    values[index] = f"vermagic={release} {suffix}".encode("ascii")

    rebuilt = b"\0".join(values) + b"\0"
    overflow = len(rebuilt) - size
    if overflow > 0:
        description = next(
            i for i, value in enumerate(values) if value.startswith(b"description=")
        )
        if len(values[description]) <= len(b"description=") + overflow:
            raise ValueError(".modinfo has no room for the requested vermagic")
        values[description] = values[description][:-overflow]
        rebuilt = b"\0".join(values) + b"\0"
    if len(rebuilt) > size:
        raise ValueError("rebuilt .modinfo is unexpectedly too large")
    data[offset : offset + size] = rebuilt.ljust(size, b"\0")
    return old, values[index].decode("ascii")


def parse_crc(value: str) -> tuple[str, int]:
    name, separator, raw_crc = value.partition("=")
    if not separator or not name:
        raise argparse.ArgumentTypeError("CRC overrides use SYMBOL=HEX")
    return name, int(raw_crc, 0)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--donor", action="append", type=Path, default=[])
    parser.add_argument("--crc", action="append", type=parse_crc, default=[])
    parser.add_argument("--release")
    args = parser.parse_args()

    data = bytearray(args.source.read_bytes())
    donor_crcs: dict[str, int] = {}
    for donor in args.donor:
        donor_crcs.update(versions(donor.read_bytes()))
    donor_crcs.update(dict(args.crc))

    changed_crcs = patch_versions(data, donor_crcs)
    vermagic_change = patch_vermagic(data, args.release) if args.release else None
    args.output.write_bytes(data)

    if vermagic_change:
        old_vermagic, new_vermagic = vermagic_change
        print(f"vermagic: {old_vermagic} -> {new_vermagic}")
    for change in changed_crcs:
        print(f"crc: {change}")
    print(f"wrote {args.output} ({len(data)} bytes)")


if __name__ == "__main__":
    main()
