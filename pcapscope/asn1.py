"""A small, defensive DER (ASN.1) decoder.

Only what Kerberos and LDAP need: a recursive tag/length/value walker that
returns a tree of :class:`Node`. Not a full ASN.1 implementation - it does not
validate, it just lets callers navigate by tag class/number.
"""

from __future__ import annotations

from dataclasses import dataclass, field

CLASS_UNIVERSAL = 0
CLASS_APPLICATION = 1
CLASS_CONTEXT = 2
CLASS_PRIVATE = 3

# universal tag numbers we care about
U_INTEGER = 2
U_BIT_STRING = 3
U_OCTET_STRING = 4
U_NULL = 5
U_OID = 6
U_ENUM = 10
U_SEQUENCE = 16
U_SET = 17
U_GENERALSTRING = 27
U_GENERALIZEDTIME = 24
U_UTCTIME = 23
U_IA5STRING = 22
U_PRINTABLESTRING = 19
U_UTF8STRING = 12


@dataclass
class Node:
    cls: int
    constructed: bool
    num: int
    content: bytes
    children: list = field(default_factory=list)
    start: int = 0
    end: int = 0

    # -- navigation helpers -------------------------------------------------
    def child(self, num: int, cls: int = CLASS_CONTEXT):
        """First child with the given tag number/class, or ``None``."""
        for c in self.children:
            if c.num == num and c.cls == cls:
                return c
        return None

    def find(self, cls: int, num: int):
        for c in self.children:
            if c.cls == cls and c.num == num:
                return c
        return None

    def unwrap(self):
        """Context-tagged values are usually [n] EXPLICIT - unwrap one level."""
        if self.constructed and len(self.children) == 1:
            return self.children[0]
        return self

    def as_int(self) -> int | None:
        b = self.content
        if not b:
            return 0
        v = int.from_bytes(b, "big", signed=True)
        return v

    def as_str(self) -> str:
        try:
            return self.content.decode("utf-8", "replace").rstrip("\x00")
        except Exception:
            return self.content.hex()


class ASN1Error(Exception):
    pass


def _parse(buf: bytes, start: int, end: int, depth: int) -> tuple[list[Node], int]:
    nodes: list[Node] = []
    i = start
    if depth > 40:
        return nodes, end
    while i < end:
        tag_start = i
        first = buf[i]
        cls = (first >> 6) & 0x03
        constructed = bool(first & 0x20)
        num = first & 0x1F
        i += 1
        if num == 0x1F:  # high-tag-number form
            num = 0
            while i < end:
                b = buf[i]
                num = (num << 7) | (b & 0x7F)
                i += 1
                if not (b & 0x80):
                    break
        if i >= end:
            break
        length_byte = buf[i]
        i += 1
        if length_byte & 0x80:
            num_octets = length_byte & 0x7F
            if num_octets == 0:
                # indefinite length - not valid in DER; bail on this element.
                break
            if i + num_octets > end:
                break
            length = int.from_bytes(buf[i : i + num_octets], "big")
            i += num_octets
        else:
            length = length_byte
        if length < 0 or i + length > end:
            # truncated/garbage - stop here, keep what we parsed.
            break
        content = buf[i : i + length]
        node = Node(cls, constructed, num, content, start=tag_start, end=i + length)
        if constructed:
            node.children, _ = _parse(buf, i, i + length, depth + 1)
        nodes.append(node)
        i += length
    return nodes, i


def parse(buf: bytes) -> list[Node]:
    """Parse a DER buffer into top-level nodes (best-effort)."""
    if not buf:
        return []
    nodes, _ = _parse(buf, 0, len(buf), 0)
    return nodes


def parse_one(buf: bytes) -> Node | None:
    nodes = parse(buf)
    return nodes[0] if nodes else None
