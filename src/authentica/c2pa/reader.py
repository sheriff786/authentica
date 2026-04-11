"""
C2PA Content Credential reader.

Reads and parses C2PA manifests embedded in images and documents.
The C2PA spec stores manifests in JUMBF (JPEG Universal Metadata Box Format)
containers. For JPEG files these live in APP11 markers; for PNG files
in iTXt chunks labeled "c2pa"; for PDF files in XMP metadata.

This module handles:
  - JPEG APP11 marker extraction
  - PNG iTXt / tEXt chunk extraction
  - CBOR decoding of JUMBF boxes
  - COSE signature structure parsing (trust verification outline)
  - Rich structured output of all C2PA assertions
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

try:
    import cbor2
    _CBOR_AVAILABLE = True
except ImportError:
    _CBOR_AVAILABLE = False


# ── JUMBF / C2PA constants ────────────────────────────────────────────────────

# JPEG APP11 marker for C2PA
_JPEG_APP11 = b"\xff\xeb"

# C2PA JUMBF UUID — identifies a C2PA manifest store box
_C2PA_UUID = bytes.fromhex("6332706100110010800000aa00389b71")

# PNG chunk type for C2PA (stored in iTXt with keyword "c2pa")
_PNG_ITXT_KEYWORD = b"c2pa"

# Known C2PA assertion label prefixes
_ASSERTION_LABELS = {
    "c2pa.actions": "Actions performed on the asset",
    "c2pa.hash.data": "Cryptographic data hash",
    "c2pa.hash.boxes": "BMFF box hash",
    "c2pa.thumbnail.claim.jpeg": "Claim thumbnail (JPEG)",
    "c2pa.thumbnail.claim.png": "Claim thumbnail (PNG)",
    "c2pa.ai.generative_info": "AI generative information",
    "c2pa.training-mining": "AI training/data mining assertions",
    "c2pa.metadata": "Asset metadata (Exif/IPTC/XMP)",
    "c2pa.ingredient": "Ingredient asset reference",
    "stds.schema-org.CreativeWork": "Schema.org CreativeWork metadata",
}


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class C2PAAssertion:
    """A single decoded assertion from a C2PA manifest."""
    label: str
    description: str
    raw: Any = field(repr=False)

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "description": self.description,
            "data": _safe_serialize(self.raw),
        }


@dataclass
class C2PAClaim:
    """A C2PA claim — the signed bundle of assertions."""
    recorder: str                      # software/hardware that created the claim
    claim_generator: str               # generator string e.g. "Adobe Photoshop"
    dc_format: str                     # asset MIME type
    assertions: list[C2PAAssertion]
    signature_info: dict[str, Any]
    raw: Any = field(repr=False)

    def to_dict(self) -> dict:
        return {
            "recorder": self.recorder,
            "claim_generator": self.claim_generator,
            "format": self.dc_format,
            "assertions": [a.to_dict() for a in self.assertions],
            "signature_info": self.signature_info,
        }


@dataclass
class C2PAResult:
    """Full result of attempting to read C2PA data from a file."""
    manifest_found: bool
    signature_valid: bool                    # True = COSE structure intact
    active_manifest_id: Optional[str]
    claims: list[C2PAClaim]
    raw_manifest_bytes: Optional[bytes] = field(default=None, repr=False)
    manifest_store: Optional[dict] = field(default=None, repr=False)
    exiftool_tags: Optional[dict[str, str]] = field(default=None, repr=False)
    data_hash_verified: Optional[bool] = None  # True/False/None if not checked
    data_hash_details: Optional[dict] = field(default=None, repr=False)
    parse_warnings: list[str] = field(default_factory=list)

    @property
    def assertions(self) -> list[C2PAAssertion]:
        """Flatten all assertions from all claims."""
        return [a for claim in self.claims for a in claim.assertions]

    @property
    def claim_generator(self) -> Optional[str]:
        """Return the claim generator of the active/first claim."""
        return self.claims[0].claim_generator if self.claims else None

    def to_dict(self) -> dict:
        base = {
            "manifest_found": self.manifest_found,
            "signature_valid": self.signature_valid,
            "active_manifest_id": self.active_manifest_id,
            "claims": [c.to_dict() for c in self.claims],
            "data_hash_verified": self.data_hash_verified,
            "warnings": self.parse_warnings,
        }
        if self.manifest_store:
            base["manifest_store"] = _safe_serialize(self.manifest_store)
        if self.exiftool_tags:
            base["exiftool_tags"] = self.exiftool_tags
        if self.data_hash_details:
            base["data_hash_details"] = _safe_serialize(self.data_hash_details)
        return base


# ── Reader ────────────────────────────────────────────────────────────────────

class C2PAReader:
    """
    Reads and decodes C2PA Content Credentials from media files.

    Supports JPEG, PNG, PDF, TIFF. Inspired by ExifTool's approach
    of walking binary containers to extract structured metadata.

    Usage:
        reader = C2PAReader()
        result = reader.read("photo.jpg")
        if result.manifest_found:
            for assertion in result.assertions:
                print(assertion.label, assertion.description)
    """

    def read(self, path: Path) -> C2PAResult:
        """Read and decode any C2PA manifest found in the file."""
        data = path.read_bytes()
        ext = path.suffix.lower()

        manifest_bytes: Optional[bytes] = None
        warnings: list[str] = []

        if data[:2] == b"\xff\xd8":
            manifest_bytes = self._extract_jpeg(data, warnings)
        elif data[:8] == b"\x89PNG\r\n\x1a\n":
            manifest_bytes = self._extract_png(data, warnings)
        elif data[:4] == b"%PDF":
            manifest_bytes = self._extract_pdf(data, warnings)
        else:
            warnings.append(f"Unsupported format (magic: {data[:4].hex()})")

        if manifest_bytes is None:
            return C2PAResult(
                manifest_found=False,
                signature_valid=False,
                active_manifest_id=None,
                claims=[],
                parse_warnings=warnings,
            )

        # Decode the JUMBF / CBOR payload
        claims, active_id, sig_valid, store, tags = self._decode_manifest(manifest_bytes, warnings)

        # Live SHA-256 data hash verification (Gap 4)
        hash_verified, hash_details = _verify_data_hash(data, claims, warnings)

        return C2PAResult(
            manifest_found=True,
            signature_valid=sig_valid,
            active_manifest_id=active_id,
            claims=claims,
            raw_manifest_bytes=manifest_bytes,
            manifest_store=store,
            exiftool_tags=tags,
            data_hash_verified=hash_verified,
            data_hash_details=hash_details,
            parse_warnings=warnings,
        )

    # ── JPEG extraction ──────────────────────────────────────────────────────

    def _extract_jpeg(self, data: bytes, warnings: list[str]) -> Optional[bytes]:
        """
        Walk JPEG markers and collect all APP11 (0xFFEB) segments
        that contain a C2PA JUMBF UUID. Multiple APP11 segments
        are concatenated in sequence-number order per the spec.
        """
        segments: dict[int, bytes] = {}   # sequence_number -> payload
        pos = 2  # skip SOI marker

        while pos < len(data) - 1:
            if data[pos] != 0xFF:
                break
            marker = data[pos : pos + 2]
            if len(data) < pos + 4:
                break
            length = struct.unpack(">H", data[pos + 2 : pos + 4])[0]
            segment_data = data[pos + 4 : pos + 2 + length]
            pos += 2 + length

            if marker != _JPEG_APP11:
                continue

            # APP11 layout: 2-byte box instance + 4-byte sequence + payload
            if len(segment_data) < 6:
                continue
            # Le (2) + CI (2) + en (2) + z (4) + LBox (4) + TBox (4) + UUID (16)
            # Minimal: CI=c2pa, en=sequence, z=total, then JUMBF
            # Per spec: APP11 = CI(2) + En(2) + Z(4) + payload
            if len(segment_data) < 8:
                continue

            ci = segment_data[0:2]
            if ci != b"\x00\x02":   # C2PA common identifier
                continue

            seq = struct.unpack(">H", segment_data[2:4])[0]
            # z = total number of APP11 segments for this JUMBF (4 bytes)
            payload = segment_data[8:]
            segments[seq] = payload

        if not segments:
            return None

        combined = b"".join(segments[k] for k in sorted(segments))

        # Verify this is a C2PA JUMBF box (UUID must match)
        if len(combined) >= 24 and combined[8:24] == _C2PA_UUID:
            return combined
        elif len(combined) >= 8:
            warnings.append("APP11 found but UUID does not match C2PA marker")
        return None

    # ── PNG extraction ───────────────────────────────────────────────────────

    def _extract_png(self, data: bytes, warnings: list[str]) -> Optional[bytes]:
        """
        Walk PNG chunks looking for an iTXt chunk with keyword 'c2pa'.
        The C2PA data is stored as compressed/uncompressed UTF-8 text
        containing a base64-encoded JUMBF, or raw binary in a caBX chunk.
        """
        pos = 8  # skip PNG signature
        while pos < len(data) - 8:
            length = struct.unpack(">I", data[pos : pos + 4])[0]
            chunk_type = data[pos + 4 : pos + 8]
            chunk_data = data[pos + 8 : pos + 8 + length]
            # CRC is 4 bytes after data
            pos += 12 + length

            if chunk_type == b"caBX":
                # Raw binary C2PA JUMBF payload
                if chunk_data:
                    return chunk_data

            if chunk_type in (b"iTXt", b"tEXt"):
                # Keyword is null-terminated
                null_idx = chunk_data.find(b"\x00")
                if null_idx == -1:
                    continue
                keyword = chunk_data[:null_idx]
                if keyword.lower() == _PNG_ITXT_KEYWORD:
                    # For iTXt: compression_flag(1) + compression_method(1) +
                    #           language(n) + \x00 + translated_keyword(n) + \x00 + text
                    if chunk_type == b"iTXt":
                        if len(chunk_data) < null_idx + 3:
                            continue
                        compression_flag = chunk_data[null_idx + 1]
                        compression_method = chunk_data[null_idx + 2]
                        text_start = null_idx + 3
                        # skip language tag and translated keyword
                        for _ in range(2):
                            nxt = chunk_data.find(b"\x00", text_start)
                            if nxt == -1:
                                break
                            text_start = nxt + 1
                        text = chunk_data[text_start:]
                        if compression_flag == 1:
                            if compression_method != 0:
                                warnings.append("PNG iTXt uses unsupported compression method")
                                continue
                            try:
                                text = zlib.decompress(text)
                            except Exception as exc:
                                warnings.append(f"PNG iTXt zlib decompress failed: {exc}")
                                continue
                        jumbf = _maybe_decode_jumbf(text, warnings)
                        if jumbf:
                            return jumbf
                    else:
                        text = chunk_data[null_idx + 1:]
                        jumbf = _maybe_decode_jumbf(text, warnings)
                        if jumbf:
                            return jumbf

            if chunk_type == b"IEND":
                break

        return None

    # ── PDF extraction ───────────────────────────────────────────────────────

    def _extract_pdf(self, data: bytes, warnings: list[str]) -> Optional[bytes]:
        """
        Look for C2PA data in a PDF. The spec embeds a C2PA manifest store
        as an associated file stream with an AFRelationship of 'C2PA_Manifest'.
        For now, scan for the JUMBF UUID magic bytes as a heuristic.
        """
        idx = data.find(_C2PA_UUID)
        if idx == -1:
            warnings.append("No C2PA JUMBF UUID found in PDF")
            return None
        # Walk back to find the box length (LBox at offset -8 from UUID)
        box_start = idx - 8
        if box_start < 0:
            return None
        lbox = struct.unpack(">I", data[box_start : box_start + 4])[0]
        return data[box_start : box_start + lbox]

    # ── JUMBF / CBOR decoding ────────────────────────────────────────────────

    def _decode_manifest(
        self,
        raw: bytes,
        warnings: list[str],
    ) -> tuple[list[C2PAClaim], Optional[str], bool, Optional[dict], Optional[dict[str, str]]]:
        """
        Decode the JUMBF manifest store into structured C2PA claims.

        JUMBF structure:
          LBox(4) TBox(4) UUID(16) [label(n)\x00] [toggle(1)] [payload...]

        C2PA manifest stores contain nested JUMBF boxes, each being
        a manifest or assertion. Payloads are CBOR-encoded.
        """
        if not _CBOR_AVAILABLE:
            warnings.append("cbor2 not installed; install with: pip install cbor2")
            return [], None, False, None, None

        try:
            return self._walk_jumbf(raw, warnings)
        except Exception as exc:
            warnings.append(f"JUMBF decode error: {exc}")
            return [], None, False, None, None

    def _walk_jumbf(
        self,
        data: bytes,
        warnings: list[str],
    ) -> tuple[list[C2PAClaim], Optional[str], bool, Optional[dict], Optional[dict[str, str]]]:
        """Walk the JUMBF box tree and decode C2PA manifest claims."""
        tree = _parse_jumbf_tree(data)
        path_map = _build_jumbf_path_map(tree)
        store = _find_manifest_store(tree)
        claims: list[C2PAClaim] = []
        active_id: Optional[str] = None
        sig_valid = False
        tags: dict[str, str] = {}

        if store:
            claims, active_id, sig_valid = self._decode_manifest_store(store, path_map, warnings)
            tags = _build_exiftool_tags(claims, warnings)
            return claims, active_id, sig_valid, store, tags

        tree_claims, tree_active, tree_sig, tree_tags = self._decode_from_tree(tree, warnings)
        if tree_claims:
            return tree_claims, tree_active, tree_sig, None, tree_tags

        # Fallback: scan all CBOR payloads for claims
        for entry in _iter_jumbf_boxes(data):
            label = entry.get("label", "")
            payload = entry.get("payload", b"")
            if not payload:
                continue
            try:
                claim = self._decode_claim(payload, label, warnings, path_map)
            except Exception as exc:
                warnings.append(f"Claim decode error ({label}): {exc}")
                continue
            if claim:
                claims.append(claim)
                if active_id is None:
                    active_id = label
                if _has_cose_tag(payload):
                    sig_valid = True

            tags = _build_exiftool_tags(claims, warnings)
            return claims, active_id, sig_valid, store, tags

    def _decode_claim(
        self,
        payload: bytes,
        label: str,
        warnings: list[str],
        path_map: Optional[dict[str, "JumbfBox"]] = None,
    ) -> Optional[C2PAClaim]:
        """Decode a single CBOR-encoded C2PA claim payload."""
        if not payload:
            return None
        try:
            cbor_data = cbor2.loads(payload)
        except Exception:
            # Payload may be nested JUMBF with a CBOR claim inside
            sub_boxes = list(_iter_jumbf_boxes(payload))
            cbor_data = None
            for box in sub_boxes:
                try:
                    cbor_data = cbor2.loads(box.get("payload", b""))
                    break
                except Exception:
                    continue
            if cbor_data is None:
                warnings.append(f"Could not decode CBOR for {label}")
                return None

        if not isinstance(cbor_data, dict):
            return None

        assertions = self._extract_assertions(cbor_data, warnings, path_map)
        recorder = cbor_data.get("dc:title", cbor_data.get("recorder", "Unknown"))
        gen = _extract_claim_generator(cbor_data)
        fmt = cbor_data.get("dc:format", cbor_data.get("format", "unknown"))
        sig_info = {
            "algorithm": cbor_data.get("alg", "unknown"),
            "issuer": cbor_data.get("cert_serial_number", "unknown"),
        }

        return C2PAClaim(
            recorder=str(recorder),
            claim_generator=str(gen),
            dc_format=str(fmt),
            assertions=assertions,
            signature_info=sig_info,
            raw=cbor_data,
        )

    def _extract_assertions(
        self,
        cbor_data: dict,
        warnings: list[str],
        path_map: Optional[dict[str, "JumbfBox"]] = None,
    ) -> list[C2PAAssertion]:
        """Pull assertion references from a CBOR claim map."""
        result: list[C2PAAssertion] = []
        raw_assertions = cbor_data.get("assertions", [])

        for item in raw_assertions:
            if not isinstance(item, dict):
                continue
            label = str(item.get("url", item.get("label", "unknown")))
            short_label = label.split("/")[-1] if "/" in label else label
            desc = _ASSERTION_LABELS.get(short_label, "Custom assertion")
            raw = item

            if path_map and isinstance(item.get("url"), str):
                resolved = _resolve_jumbf_uri(item["url"], path_map, warnings)
                if resolved is not None:
                    raw = resolved

            result.append(C2PAAssertion(label=short_label, description=desc, raw=raw))

        return result

    def _decode_manifest_store(
        self,
        store: dict,
        path_map: dict[str, "JumbfBox"],
        warnings: list[str],
    ) -> tuple[list[C2PAClaim], Optional[str], bool]:
        """Decode manifest store map into claims and assertions."""
        claims: list[C2PAClaim] = []
        active_id: Optional[str] = None
        sig_valid = False

        active_id = store.get("active_manifest") or store.get("activeManifest")
        manifests = store.get("manifests") or store.get("manifest_store") or {}
        if not isinstance(manifests, dict):
            warnings.append("C2PA manifest store missing manifests map")
            return claims, active_id, sig_valid

        for manifest_id, manifest in manifests.items():
            if not isinstance(manifest, dict):
                continue
            claim_ref = manifest.get("claim")
            claim_payload = None

            if isinstance(claim_ref, str):
                claim_payload = _resolve_jumbf_uri(claim_ref, path_map, warnings)
            elif isinstance(claim_ref, (bytes, bytearray)):
                claim_payload = bytes(claim_ref)
            elif isinstance(claim_ref, dict):
                claim_payload = claim_ref

            if claim_payload is None:
                continue

            if isinstance(claim_payload, dict):
                claim_data = claim_payload
            else:
                try:
                    claim_data = cbor2.loads(claim_payload)
                except Exception as exc:
                    warnings.append(f"Claim CBOR decode error ({manifest_id}): {exc}")
                    continue

            claim = self._decode_claim_from_map(claim_data, warnings, path_map)
            if claim:
                claims.append(claim)
                if active_id is None:
                    active_id = str(manifest_id)
                if _has_cose_tag(_safe_bytes(claim_payload)):
                    sig_valid = True

        return claims, active_id, sig_valid

    def _decode_claim_from_map(
        self,
        cbor_data: dict,
        warnings: list[str],
        path_map: dict[str, "JumbfBox"],
    ) -> Optional[C2PAClaim]:
        if not isinstance(cbor_data, dict):
            return None
        assertions = self._extract_assertions(cbor_data, warnings, path_map)
        recorder = cbor_data.get("dc:title", cbor_data.get("recorder", "Unknown"))
        gen = _extract_claim_generator(cbor_data)
        fmt = cbor_data.get("dc:format", cbor_data.get("format", "unknown"))
        sig_info = {
            "algorithm": cbor_data.get("alg", "unknown"),
            "issuer": cbor_data.get("cert_serial_number", "unknown"),
        }

        return C2PAClaim(
            recorder=str(recorder),
            claim_generator=str(gen),
            dc_format=str(fmt),
            assertions=assertions,
            signature_info=sig_info,
            raw=cbor_data,
        )

    def _decode_from_tree(
        self,
        tree: list["JumbfBox"],
        warnings: list[str],
    ) -> tuple[list[C2PAClaim], Optional[str], bool, dict[str, str]]:
        """Decode manifests directly from the JUMBF tree."""
        claims: list[C2PAClaim] = []
        active_id: Optional[str] = None
        sig_valid = False

        root = _find_root_c2pa(tree)
        if not root:
            return claims, active_id, sig_valid, {}

        for manifest in root.children:
            if manifest.box_type != "jumb" or not manifest.label.startswith("urn:c2pa:"):
                continue
            claim_node = _find_child_manifest_node(manifest, "c2pa.claim.v2")
            if not claim_node:
                continue
            claim_map = _decode_first_cbor_in_box(claim_node, warnings)
            if not isinstance(claim_map, dict):
                continue

            assertions = self._collect_assertions_from_manifest(manifest, warnings)
            claim = self._decode_claim_from_map(claim_map, warnings, _build_jumbf_path_map(tree))
            if claim:
                claim.assertions = assertions
                claims.append(claim)
                if active_id is None:
                    active_id = manifest.label

            sig_node = _find_child_manifest_node(manifest, "c2pa.signature")
            sig_payload = _decode_first_payload_in_box(sig_node) if sig_node else b""
            if sig_payload and _has_cose_tag(sig_payload):
                sig_valid = True

        tags = _build_exiftool_tags(claims, warnings)
        return claims, active_id, sig_valid, tags

    def _collect_assertions_from_manifest(
        self,
        manifest: "JumbfBox",
        warnings: list[str],
    ) -> list[C2PAAssertion]:
        assertions: list[C2PAAssertion] = []
        assertions_node = _find_child_manifest_node(manifest, "c2pa.assertions")
        if not assertions_node:
            return assertions

        for child in assertions_node.children:
            if child.box_type != "jumb":
                continue
            label = child.label
            raw = _decode_first_cbor_in_box(child, warnings)
            if raw is None:
                if label == "c2pa.thumbnail.ingredient":
                    raw = _extract_thumbnail_payload(child)
                else:
                    payload = _decode_first_payload_in_box(child)
                    raw = payload if payload else None
            desc = _ASSERTION_LABELS.get(label, "Custom assertion")
            assertions.append(C2PAAssertion(label=label, description=desc, raw=raw))

        return assertions


# ── JUMBF walking utilities ───────────────────────────────────────────────────

@dataclass
class JumbfBox:
    box_type: str
    label: str
    uuid: Optional[str]
    payload: bytes = field(repr=False)
    children: list["JumbfBox"] = field(default_factory=list, repr=False)

def _iter_jumbf_boxes(data: bytes):
    """
    Yield JUMBF boxes from raw bytes.

    JUMBF box layout (ISO 19566-5):
      LBox   : 4 bytes, big-endian uint32 — total box size including LBox+TBox
      TBox   : 4 bytes — box type ('jumb', 'jumd', 'cbor', 'json', etc.)
      [UUID  : 16 bytes — present when TBox == 'jumd']
      [toggle: 1 byte — toggles: label present bit (0x02), requestable (0x01)]
      [label : null-terminated string — present when toggle & 0x02]
      payload: remaining bytes
    """
    pos = 0
    while pos < len(data) - 7:
        if len(data) - pos < 8:
            break
        lbox = struct.unpack(">I", data[pos : pos + 4])[0]
        tbox = data[pos + 4 : pos + 8]

        if lbox == 0:
            break   # lbox==0 means "to end of file"; stop iterating
        if lbox < 8 or pos + lbox > len(data):
            break

        box_data = data[pos + 8 : pos + lbox]

        if tbox == b"jumd":
            # Description box: UUID(16) + toggle(1) + label(n\x00) + sub-boxes
            if len(box_data) >= 17:
                uuid = box_data[:16]
                toggle = box_data[16]
                rest = box_data[17:]
                label = ""
                if toggle & 0x02:
                    null_idx = rest.find(b"\x00")
                    if null_idx != -1:
                        label = rest[:null_idx].decode("utf-8", errors="replace")
                        rest = rest[null_idx + 1:]
                yield {"type": "jumd", "uuid": uuid.hex(), "label": label, "payload": rest}
        elif tbox in (b"cbor", b"json"):
            yield {"type": tbox.decode(), "label": "", "payload": box_data}
        elif tbox == b"jumb":
            # Superbox — recurse
            yield from _iter_jumbf_boxes(box_data)

        pos += lbox


def _extract_claim_generator(cbor_data: dict) -> str:
    """
    Extract claim generator name from C2PA claim CBOR map.

    C2PA v2 spec uses 'claimGeneratorInfo' which is a list of objects,
    each with a 'name' sub-field. Falls back to 'claim_generator' /
    'claimGenerator' string keys for v1 compatibility.
    """
    # C2PA v2: claimGeneratorInfo is a list of dicts with 'name'
    gen_info = cbor_data.get("claimGeneratorInfo") or cbor_data.get("claim_generator_info")
    if isinstance(gen_info, list) and gen_info:
        first = gen_info[0]
        if isinstance(first, dict):
            name = first.get("name")
            if name:
                return str(name)
    elif isinstance(gen_info, dict):
        name = gen_info.get("name")
        if name:
            return str(name)

    # C2PA v1 fallback: plain string
    gen = cbor_data.get("claim_generator") or cbor_data.get("claimGenerator")
    if gen:
        return str(gen)
    return "Unknown"


def _verify_data_hash(
    file_data: bytes,
    claims: list[C2PAClaim],
    warnings: list[str],
) -> tuple[Optional[bool], Optional[dict]]:
    """
    Verify the embedded C2PA data hash against the actual file bytes.

    Reads the c2pa.hash.data assertion to find the expected hash,
    algorithm, and exclusion ranges. Computes the hash over the file
    bytes with the JUMBF exclusion ranges zeroed out, then compares.

    Returns (verified: bool | None, details: dict | None).
    """
    hash_assertion = None
    for claim in claims:
        for assertion in claim.assertions:
            if assertion.label == "c2pa.hash.data" and isinstance(assertion.raw, dict):
                hash_assertion = assertion.raw
                break
        if hash_assertion:
            break

    if hash_assertion is None:
        return None, None

    expected_hash = hash_assertion.get("hash")
    algorithm = hash_assertion.get("alg", "sha256")
    exclusions = hash_assertion.get("exclusions", [])
    name = hash_assertion.get("name", "jumbf manifest")
    pad = hash_assertion.get("pad")

    if not isinstance(expected_hash, (bytes, bytearray)):
        warnings.append("c2pa.hash.data has no binary hash value")
        return None, None

    # Map algorithm name to hashlib
    alg_map = {"sha256": "sha256", "sha384": "sha384", "sha512": "sha512"}
    hash_name = alg_map.get(algorithm.lower().replace("-", ""))
    if not hash_name:
        warnings.append(f"Unsupported hash algorithm: {algorithm}")
        return None, {"algorithm": algorithm, "supported": False}

    # Build the byte stream with exclusion ranges replaced by zeroes
    modified_data = bytearray(file_data)
    exclusion_details = []
    for ex in exclusions:
        if not isinstance(ex, dict):
            continue
        start = ex.get("start", ex.get("offset", 0))
        length = ex.get("length", 0)
        if start is not None and length:
            start = int(start)
            length = int(length)
            if 0 <= start < len(modified_data) and start + length <= len(modified_data):
                modified_data[start:start + length] = b"\x00" * length
                exclusion_details.append({"start": start, "length": length})

    # Compute the hash
    h = hashlib.new(hash_name)
    h.update(bytes(modified_data))
    computed_hash = h.digest()

    verified = computed_hash == bytes(expected_hash)

    details = {
        "algorithm": algorithm,
        "expected_hash": bytes(expected_hash).hex(),
        "computed_hash": computed_hash.hex(),
        "match": verified,
        "exclusions": exclusion_details,
        "name": name,
    }

    if not verified:
        warnings.append(
            f"assertion.dataHash MISMATCH: expected {bytes(expected_hash).hex()[:16]}... "
            f"got {computed_hash.hex()[:16]}..."
        )
    else:
        # Add to exiftool-style output
        pass  # The match result is in the details

    return verified, details


def _has_cose_tag(data: bytes) -> bool:
    """Heuristic: CBOR COSE_Sign1 starts with tag 18 (0xd2) or 98 (0xd8 0x62)."""
    return b"\xd2\x84" in data or b"\xd8\x62" in data


def _safe_serialize(obj: Any) -> Any:
    """Recursively convert CBOR types to JSON-serialisable Python types."""
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, dict):
        return {str(k): _safe_serialize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_safe_serialize(i) for i in obj]
    return obj


def _parse_jumbf_tree(data: bytes) -> list[JumbfBox]:
    """Parse raw JUMBF bytes into a tree of boxes."""
    return _parse_jumbf_box_stream(data)


def _parse_jumbf_box_stream(data: bytes) -> list[JumbfBox]:
    boxes: list[JumbfBox] = []
    pos = 0
    while pos < len(data) - 7:
        if len(data) - pos < 8:
            break
        lbox = struct.unpack(">I", data[pos : pos + 4])[0]
        tbox = data[pos + 4 : pos + 8]

        if lbox == 0:
            break
        if lbox < 8 or pos + lbox > len(data):
            break

        box_data = data[pos + 8 : pos + lbox]
        pos += lbox

        if tbox == b"jumb":
            children = _parse_jumbf_box_stream(box_data)
            label = ""
            uuid = None
            filtered_children: list[JumbfBox] = []
            for child in children:
                if child.box_type == "jumd":
                    label = child.label
                    uuid = child.uuid
                else:
                    filtered_children.append(child)
            boxes.append(JumbfBox(box_type="jumb", label=label, uuid=uuid,
                                  payload=b"", children=filtered_children))
            continue

        if tbox == b"jumd":
            label, uuid = _parse_jumd(box_data)
            boxes.append(JumbfBox(box_type="jumd", label=label, uuid=uuid, payload=box_data))
            continue

        if tbox in (b"cbor", b"json"):
            boxes.append(JumbfBox(box_type=tbox.decode(), label="", uuid=None, payload=box_data))
            continue

        # Preserve unknown box types to keep binary payloads (eg. thumbnails)
        box_type = tbox.decode("latin-1", errors="replace")
        boxes.append(JumbfBox(box_type=box_type, label="", uuid=None, payload=box_data))
        continue

    return boxes


def _parse_jumd(data: bytes) -> tuple[str, Optional[str]]:
    """Parse a JUMBF description box for label and UUID."""
    if len(data) < 17:
        return "", None
    uuid = data[:16].hex()
    toggle = data[16]
    rest = data[17:]
    label = ""
    if toggle & 0x02:
        null_idx = rest.find(b"\x00")
        if null_idx != -1:
            label = rest[:null_idx].decode("utf-8", errors="replace")
    return label, uuid


def _build_jumbf_path_map(tree: list[JumbfBox]) -> dict[str, JumbfBox]:
    """Build a path -> JUMBF box map from the tree using label hierarchy."""
    path_map: dict[str, JumbfBox] = {}

    def visit(node: JumbfBox, prefix: str) -> None:
        current = prefix
        if node.box_type == "jumb" and node.label:
            current = f"{prefix}/{node.label}" if prefix else node.label
            path_map[current] = node
        for child in node.children:
            visit(child, current)

    for root in tree:
        visit(root, "")

    return path_map


def _find_manifest_store(tree: list[JumbfBox]) -> Optional[dict]:
    """Locate and decode the C2PA manifest store CBOR map."""
    for node in tree:
        store = _find_manifest_store_in_node(node)
        if store is not None:
            return store
    return None


def _find_manifest_store_in_node(node: JumbfBox) -> Optional[dict]:
    if node.box_type == "jumb" and (node.label == "c2pa" or node.uuid == _C2PA_UUID.hex()):
        for child in node.children:
            if child.box_type == "cbor":
                try:
                    return cbor2.loads(child.payload)
                except Exception:
                    return None
            if child.box_type == "jumb":
                found = _find_manifest_store_in_node(child)
                if found is not None:
                    return found
    for child in node.children:
        found = _find_manifest_store_in_node(child)
        if found is not None:
            return found
    return None


def _resolve_jumbf_uri(uri: str, path_map: dict[str, JumbfBox], warnings: list[str]) -> Optional[dict | bytes]:
    """Resolve a JUMBF URI to CBOR payload or raw bytes."""
    if "#jumbf=" not in uri:
        return None
    path = uri.split("#jumbf=")[-1]
    if path.startswith("/"):
        path = path[1:]

    box = path_map.get(path)
    if not box:
        # Try to resolve from a partial path
        for key in path_map:
            if key.endswith(path):
                box = path_map[key]
                break
    if not box:
        return None

    for child in box.children:
        if child.box_type == "cbor":
            try:
                return cbor2.loads(child.payload)
            except Exception as exc:
                warnings.append(f"Assertion CBOR decode failed: {exc}")
                return child.payload
    return None


def _find_root_c2pa(tree: list[JumbfBox]) -> Optional[JumbfBox]:
    for node in tree:
        if node.box_type == "jumb" and node.label == "c2pa":
            return node
    return None


def _find_child_manifest_node(parent: JumbfBox, label: str) -> Optional[JumbfBox]:
    for child in parent.children:
        if child.box_type == "jumb" and child.label == label:
            return child
    return None


def _decode_first_cbor_in_box(node: Optional[JumbfBox], warnings: list[str]) -> Optional[dict]:
    if not node:
        return None
    for child in node.children:
        if child.box_type == "cbor":
            try:
                return cbor2.loads(child.payload)
            except Exception as exc:
                warnings.append(f"CBOR decode failed: {exc}")
                return None
    return None


def _decode_first_payload_in_box(node: Optional[JumbfBox]) -> bytes:
    if not node:
        return b""
    # Prefer embedded data boxes if present
    for child in node.children:
        if child.box_type == "bidb" and child.payload:
            return child.payload
    for child in node.children:
        if child.box_type == "bfdb" and child.payload:
            return child.payload
    for child in node.children:
        if child.payload:
            return child.payload
    return b""


def _build_exiftool_tags(claims: list[C2PAClaim], warnings: list[str]) -> dict[str, str]:
    """Flatten parsed claims/assertions to ExifTool-like tag names."""
    tags: dict[str, str] = {}

    if claims:
        tags["JUMD Type"] = f"(c2pa)-{_C2PA_UUID.hex()}"
        tags["JUMD Label"] = "c2pa"

    actions_list: list[str] = []
    software_agents: list[str] = []
    digital_sources: list[str] = []
    ingredient_urls: list[str] = []
    ingredient_hashes: list[str] = []

    exclusions_start: list[str] = []
    exclusions_length: list[str] = []
    hash_names: list[str] = []
    hash_algs: list[str] = []
    hash_values: list[str] = []
    hash_pads: list[str] = []

    instance_ids: list[str] = []
    claim_gen_names: list[str] = []
    claim_gen_orgs: list[str] = []
    signatures: list[str] = []
    created_assertion_urls: list[str] = []
    created_assertion_hashes: list[str] = []
    titles: list[str] = []

    thumbnail_salts: list[str] = []
    thumbnail_types: list[str] = []
    thumbnail_datas: list[str] = []

    validation_codes: list[str] = []
    validation_urls: list[str] = []
    validation_explanations: list[str] = []
    active_manifest_urls: list[str] = []
    active_manifest_algs: list[str] = []
    active_manifest_hashes: list[str] = []
    claim_sig_urls: list[str] = []
    claim_sig_algs: list[str] = []
    claim_sig_hashes: list[str] = []
    thumb_urls: list[str] = []
    thumb_hashes: list[str] = []
    relationships: list[str] = []
    formats: list[str] = []

    for claim in claims:
        raw = claim.raw if isinstance(claim.raw, dict) else {}
        instance_id = raw.get("instanceID")
        if instance_id:
            instance_ids.append(str(instance_id))
        claim_gen = raw.get("claim_generator_info") or {}
        if isinstance(claim_gen, dict):
            name = claim_gen.get("name")
            if name:
                claim_gen_names.append(str(name))
            org = claim_gen.get("org.contentauth.c2pa_rs")
            if org:
                claim_gen_orgs.append(str(org))
        sig = raw.get("signature")
        if sig:
            signatures.append(str(sig))
        created = raw.get("created_assertions", [])
        if isinstance(created, list):
            for item in created:
                if not isinstance(item, dict):
                    continue
                url = item.get("url")
                if url:
                    created_assertion_urls.append(str(url))
                h = item.get("hash")
                if isinstance(h, (bytes, bytearray)):
                    created_assertion_hashes.append(h.hex())
        title = raw.get("dc:title")
        if title:
            titles.append(str(title))

        for assertion in claim.assertions:
            label = assertion.label
            data = assertion.raw
            if label.startswith("c2pa.actions") and isinstance(data, dict):
                actions = data.get("actions", [])
                for act in actions:
                    if not isinstance(act, dict):
                        continue
                    action_name = act.get("action")
                    if action_name:
                        actions_list.append(str(action_name))
                    agent = act.get("softwareAgent", {})
                    if isinstance(agent, dict) and agent.get("name"):
                        software_agents.append(str(agent["name"]))
                    dst = act.get("digitalSourceType")
                    if dst:
                        digital_sources.append(str(dst))
                    params = act.get("parameters", {})
                    if isinstance(params, dict):
                        ingredients = params.get("ingredients", [])
                        for ing in ingredients:
                            if not isinstance(ing, dict):
                                continue
                            if ing.get("url"):
                                ingredient_urls.append(str(ing["url"]))
                            h = ing.get("hash")
                            if isinstance(h, (bytes, bytearray)):
                                ingredient_hashes.append(h.hex())

            if label == "c2pa.hash.data" and isinstance(data, dict):
                exclusions = data.get("exclusions", [])
                for ex in exclusions:
                    if isinstance(ex, dict):
                        if ex.get("start") is not None:
                            exclusions_start.append(str(ex.get("start")))
                        if ex.get("length") is not None:
                            exclusions_length.append(str(ex.get("length")))
                if data.get("name"):
                    hash_names.append(str(data["name"]))
                if data.get("alg"):
                    hash_algs.append(str(data["alg"]))
                if isinstance(data.get("hash"), (bytes, bytearray)):
                    hash_values.append(data["hash"].hex())
                if isinstance(data.get("pad"), (bytes, bytearray)):
                    hash_pads.append(data["pad"].hex())

            if label == "c2pa.ingredient.v3" and isinstance(data, dict):
                if data.get("relationship"):
                    relationships.append(str(data.get("relationship")))
                if data.get("dc:format"):
                    formats.append(str(data.get("dc:format")))

                val = data.get("validationResults", {})
                success = val.get("activeManifest", {}).get("success", []) if isinstance(val, dict) else []
                for s in success:
                    if not isinstance(s, dict):
                        continue
                    if s.get("code"):
                        validation_codes.append(str(s.get("code")))
                    if s.get("url"):
                        validation_urls.append(str(s.get("url")))
                    if s.get("explanation"):
                        validation_explanations.append(str(s.get("explanation")))

                active = data.get("activeManifest", {}) if isinstance(data.get("activeManifest"), dict) else {}
                if active.get("url"):
                    active_manifest_urls.append(str(active.get("url")))
                if active.get("alg"):
                    active_manifest_algs.append(str(active.get("alg")))
                if isinstance(active.get("hash"), (bytes, bytearray)):
                    active_manifest_hashes.append(active.get("hash").hex())

                cs = data.get("claimSignature", {}) if isinstance(data.get("claimSignature"), dict) else {}
                if cs.get("url"):
                    claim_sig_urls.append(str(cs.get("url")))
                if cs.get("alg"):
                    claim_sig_algs.append(str(cs.get("alg")))
                if isinstance(cs.get("hash"), (bytes, bytearray)):
                    claim_sig_hashes.append(cs.get("hash").hex())

                th = data.get("thumbnail", {}) if isinstance(data.get("thumbnail"), dict) else {}
                if th.get("url"):
                    thumb_urls.append(str(th.get("url")))
                if isinstance(th.get("hash"), (bytes, bytearray)):
                    thumb_hashes.append(th.get("hash").hex())

            if label == "c2pa.thumbnail.ingredient":
                if isinstance(data, dict):
                    if data.get("type"):
                        thumbnail_types.append(str(data.get("type")))
                    if isinstance(data.get("data"), (bytes, bytearray)):
                        thumbnail_datas.append(_binary_hint(data["data"]))
                    if data.get("salt"):
                        thumbnail_salts.append(str(data.get("salt")))
                elif isinstance(data, (bytes, bytearray)):
                    thumbnail_datas.append(_binary_hint(data))
                    if data[:2] == b"\xff\xd8":
                        thumbnail_types.append("image/jpeg")

    def put(name: str, values: list[str]) -> None:
        if not values:
            return
        tags[name] = ", ".join(values)

    put("Actions Action", actions_list)
    put("Actions Software Agent Name", software_agents)
    put("Actions Digital Source Type", digital_sources)
    put("Actions Parameters Ingredients Url", ingredient_urls)
    put("Actions Parameters Ingredients Hash", ingredient_hashes)
    put("Exclusions Start", exclusions_start)
    put("Exclusions Length", exclusions_length)
    put("Name", hash_names)
    put("Alg", hash_algs)
    put("Hash", hash_values)
    put("Pad", hash_pads)
    put("Instance ID", instance_ids)
    put("Claim Generator Info Name", claim_gen_names)
    put("Claim Generator Info Org Contentauth C2 Pa Rs", claim_gen_orgs)
    put("Signature", signatures)
    put("Created Assertions Url", created_assertion_urls)
    put("Created Assertions Hash", created_assertion_hashes)
    put("Title", titles)
    put("C2PA Thumbnail Ingredient Salt", thumbnail_salts)
    put("C2PA Thumbnail Ingredient Type", thumbnail_types)
    put("C2PA Thumbnail Ingredient Data", thumbnail_datas)
    put("Relationship", relationships)
    put("Format", formats)
    put("Validation Results Active Manifest Success Code", validation_codes)
    put("Validation Results Active Manifest Success Url", validation_urls)
    put("Validation Results Active Manifest Success Explanation", validation_explanations)
    put("Active Manifest Url", active_manifest_urls)
    put("Active Manifest Alg", active_manifest_algs)
    put("Active Manifest Hash", active_manifest_hashes)
    put("Claim Signature Url", claim_sig_urls)
    put("Claim Signature Alg", claim_sig_algs)
    put("Claim Signature Hash", claim_sig_hashes)
    put("Thumbnail URL", thumb_urls)
    put("Thumbnail Hash", thumb_hashes)

    if not tags:
        warnings.append("C2PA tags decoded but no ExifTool-style fields mapped")
    return tags


def _binary_hint(data: bytes) -> str:
    return f"(Binary data {len(data)} bytes)"


def _extract_thumbnail_payload(node: JumbfBox) -> dict:
    """Extract thumbnail payload and metadata from a thumbnail assertion box."""
    mime_type = None
    data = None

    for child in node.children:
        if child.box_type == "bfdb" and child.payload:
            # bfdb payload: 0x00 + mime string + 0x00
            raw = child.payload
            if len(raw) > 1:
                mime_type = raw[1:].decode("utf-8", errors="replace").strip("\x00")
        if child.box_type == "bidb" and child.payload:
            data = child.payload

    return {"type": mime_type, "data": data}


def _safe_bytes(value: object) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, dict):
        return b""
    return b""


def _maybe_decode_jumbf(payload: bytes, warnings: list[str]) -> Optional[bytes]:
    """
    Return raw JUMBF bytes from a payload, handling base64-encoded text.
    """
    if not payload:
        return None

    if len(payload) >= 8 and payload[4:8] == b"jumb":
        return payload

    # Try base64 decode of UTF-8 text payloads
    try:
        text = payload.decode("utf-8").strip()
    except Exception:
        return None

    if not _is_base64ish(text):
        return None

    try:
        decoded = base64.b64decode(text, validate=False)
    except Exception as exc:
        warnings.append(f"Base64 decode failed: {exc}")
        return None

    if len(decoded) >= 8 and decoded[4:8] == b"jumb":
        return decoded

    return None


def _is_base64ish(text: str) -> bool:
    """Heuristic check for base64-like text without heavy parsing."""
    if not text:
        return False
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\r\n")
    return all(ch in allowed for ch in text)
