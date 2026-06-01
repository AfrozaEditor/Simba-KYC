"""Service MRZ ICAO (detection, parsing, checksums)."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple


class MRZService:
    """Analyse des lignes MRZ et verification des checksums ICAO 9303."""

    WEIGHTS: Tuple[int, int, int] = (7, 3, 1)
    OCR_NUMERIC_MAP: Dict[str, str] = {
        "O": "0",
        "Q": "0",
        "D": "0",
        "I": "1",
        "L": "1",
        "Z": "2",
        "S": "5",
        "B": "8",
        "G": "6",
    }

    def analyze(
        self,
        *,
        mrz_lines: Optional[Sequence[str]] = None,
        raw_text: str = "",
        expected: bool = False,
    ) -> Dict[str, Any]:
        """Retourne une analyse MRZ tolerante aux erreurs."""

        result: Dict[str, Any] = {
            "expected": bool(expected),
            "detected": False,
            "parseable": False,
            "format": None,
            "raw_lines": [],
            "parsed_fields": {},
            "checksums": {
                "document_number": self._empty_check(),
                "date_of_birth": self._empty_check(),
                "expiry_date": self._empty_check(),
                "composite": self._empty_check(),
            },
            "error": None,
        }

        candidate_lines = self._collect_candidate_lines(mrz_lines=mrz_lines, raw_text=raw_text)
        if candidate_lines:
            result["detected"] = True
            result["raw_lines"] = candidate_lines
        else:
            if expected:
                result["error"] = "mrz_not_detected"
            return result

        parsed = self._parse_candidate_lines(candidate_lines)
        if parsed is None:
            result["error"] = "mrz_not_parseable"
            return result

        result["parseable"] = True
        result["format"] = parsed["format"]
        result["parsed_fields"] = parsed["parsed_fields"]
        result["checksums"] = parsed["checksums"]
        return result

    def _collect_candidate_lines(self, *, mrz_lines: Optional[Sequence[str]], raw_text: str) -> List[str]:
        source_lines: List[str] = []

        if mrz_lines:
            for line in mrz_lines:
                if line:
                    source_lines.extend(line.splitlines())

        if raw_text:
            source_lines.extend(raw_text.splitlines())

        if not source_lines:
            return []

        nonempty_lines = [line for line in source_lines if line]
        has_td3_header = any(self._sanitize_line(line).startswith("P<") for line in nonempty_lines)
        allow_split_td1 = len(nonempty_lines) < 3 and not has_td3_header

        cleaned: List[str] = []
        for line in source_lines:
            if not line:
                continue
            sanitized = self._sanitize_line(line)
            if not sanitized:
                continue
            repaired = self._repair_icao_prefix(sanitized)
            cleaned.extend(self._expand_mrz_line(repaired, allow_split_td1))

        candidates = [line for line in cleaned if self._looks_like_mrz_line(line)]
        if not candidates:
            recovered = self._recover_mrz_lines(raw_text)
            candidates = [line for line in recovered if self._looks_like_mrz_line(line)]
        if not candidates:
            return []

        normalized: List[str] = []
        previous_was_td3_header = False
        for line in candidates:
            is_td3_line = line.startswith("P<") or previous_was_td3_header
            target_length = 44 if is_td3_line else 30

            if len(line) != target_length:
                line = self._fit_mrz_line_length(line, target_length)
            normalized.append(line)
            previous_was_td3_header = line.startswith("P<")

        dedup_lines: List[str] = []
        seen = set()
        for line in normalized:
            if line not in seen:
                seen.add(line)
                dedup_lines.append(line)

        return dedup_lines

    @classmethod
    def _recover_mrz_lines(cls, raw_text: str) -> List[str]:
        if not raw_text:
            return []

        recovered: List[str] = []

        for line in raw_text.splitlines():
            normalized = cls._sanitize_line(line)
            if not normalized:
                continue
            if normalized.startswith("I<CMR") or normalized.startswith("P<"):
                recovered.append(normalized)
                continue
            if "I<CMR" in normalized:
                idx = normalized.find("I<CMR")
                recovered.append(normalized[idx:])

        if not recovered:
            compact = cls._sanitize_line(raw_text)
            for match in re.findall(r"P<[<A-Z0-9]{70,120}", compact):
                recovered.append(match)
            for match in re.findall(r"I<CMR[<A-Z0-9]{20,120}", compact):
                recovered.append(match)

        if recovered:
            expanded: List[str] = []
            for line in recovered:
                if line.startswith("P<") and len(line) >= 88:
                    expanded.extend([line[0:44], line[44:88]])
                elif len(line) >= 90:
                    expanded.extend([line[0:30], line[30:60], line[60:90]])
                else:
                    expanded.append(line)
            recovered = expanded

        return recovered

    @staticmethod
    def _looks_like_mrz_line(line: str) -> bool:
        """Filtre les lignes OCR bruitées en conservant des signatures MRZ minimales."""

        if not line or not (10 <= len(line) <= 44):
            return False

        # Sans filler '<', ce n'est pratiquement jamais une MRZ exploitable.
        if "<" not in line and not line.startswith(("P<", "I<", "A<", "C<", "V<")):
            return False

        # Prefixes fréquents de première ligne ICAO.
        if line.startswith(("P<", "I<", "A<", "C<", "V<")):
            return True

        # Heuristique pour les lignes 2/3: mélange chiffres + fillers.
        filler_count = line.count("<")
        digit_count = sum(1 for char in line if char.isdigit())
        has_name_separator = "<<" in line
        return filler_count >= 2 and (digit_count >= 2 or (has_name_separator and filler_count >= 4))

    @staticmethod
    def _repair_icao_prefix(line: str) -> str:
        if not line:
            return ""

        if line.startswith(("P<", "I<", "A<", "C<", "V<")):
            return line

        if len(line) >= 4 and line[0] in {"I", "A", "C"} and line[1].isalpha() and line[2:4].isalpha():
            return f"{line[0]}<{line[1:]}"

        return line

    @staticmethod
    def _expand_mrz_line(line: str, allow_split_td1: bool) -> List[str]:
        if not line:
            return []

        if len(line) > 44:
            chunk_size = 44 if line.startswith("P<") else 30
            return [line[i : i + chunk_size] for i in range(0, len(line), chunk_size) if line[i : i + chunk_size]]

        if allow_split_td1 and len(line) > 30 and not line.startswith("P<"):
            head = line[:30]
            tail = line[30:]
            return [segment for segment in (head, tail) if segment]

        return [line]

    def _parse_candidate_lines(self, lines: Sequence[str]) -> Optional[Dict[str, Any]]:
        # TD1: 3 lignes x 30 (carte identite)
        for i in range(0, len(lines) - 2):
            line1 = lines[i]
            line2 = lines[i + 1]
            line3 = lines[i + 2]
            if len(line1) == 30 and len(line2) == 30 and len(line3) == 30:
                return self._parse_td1(line1, line2, line3)

        # TD1 tolerant: OCR peut ajouter/supprimer des fillers sur des CNI.
        for i in range(0, len(lines) - 2):
            line1 = lines[i]
            line2 = lines[i + 1]
            line3 = lines[i + 2]

            if not line1.startswith(("I<", "A<", "C<")):
                continue

            if not all(28 <= len(line) <= 34 for line in (line1, line2, line3)):
                continue

            line1_td1 = self._fit_mrz_line_length(line1, 30)
            line2_td1 = self._fit_mrz_line_length(line2, 30)
            line3_td1 = self._fit_mrz_line_length(line3, 30)
            return self._parse_td1(line1_td1, line2_td1, line3_td1)

        # TD3: 2 lignes x 44 (passeport)
        for i in range(0, len(lines) - 1):
            line1 = lines[i]
            line2 = lines[i + 1]
            if len(line1) == 44 and len(line2) == 44 and line1.startswith("P<"):
                return self._parse_td3(line1, line2)

        return None

    def _parse_td3(self, line1: str, line2: str) -> Dict[str, Any]:
        line2_for_checks = self._normalize_td3_numeric_fields(line2)

        doc_number = line2_for_checks[0:9]
        doc_number_check = line2_for_checks[9]
        nationality = line2[10:13]
        birth_raw = line2_for_checks[13:19]
        birth_check = line2_for_checks[19]
        sex = line2[20]
        expiry_raw = line2_for_checks[21:27]
        expiry_check = line2_for_checks[27]
        optional = line2[28:42]
        optional_check = self._normalize_check_char(line2[42])
        composite_raw = line2_for_checks[0:10] + line2_for_checks[13:20] + line2_for_checks[21:43]
        composite_check = self._normalize_check_char(line2[43])

        surname, given_names = self._parse_name_field(line1[5:44])

        checks = {
            "document_number": self._compute_check(data=doc_number, check_char=doc_number_check),
            "date_of_birth": self._compute_check(data=birth_raw, check_char=birth_check),
            "expiry_date": self._compute_check(data=expiry_raw, check_char=expiry_check),
            "composite": self._compute_check(data=composite_raw, check_char=composite_check),
        }

        parsed_fields = {
            "document_number": self._clean_field(doc_number),
            "date_of_birth": self._parse_mrz_date(birth_raw, prefer_past=True),
            "expiry_date": self._parse_mrz_date(expiry_raw, prefer_past=False),
            "country": self._clean_field(line1[2:5]),
            "nationality": self._clean_field(nationality),
            "sex": self._clean_field(sex),
            "last_name": surname,
            "first_name": given_names,
            "full_name": f"{given_names} {surname}".strip(),
            "optional_data": self._clean_field(optional),
            "optional_data_check": optional_check,
        }

        parsed_fields["optional_data_check_valid"] = self._compute_check(data=optional, check_char=optional_check)["valid"]

        return {
            "format": "TD3",
            "parsed_fields": parsed_fields,
            "checksums": checks,
        }

    def _parse_td1(self, line1: str, line2: str, line3: str) -> Dict[str, Any]:
        line1_for_checks = self._normalize_td1_line1_numeric_fields(line1)
        line2_for_checks = self._normalize_td1_line2_numeric_fields(line2)

        doc_number = line1_for_checks[5:14]
        doc_number_check = line1_for_checks[14]
        birth_raw = line2_for_checks[0:6]
        birth_check = line2_for_checks[6]
        sex = line2[7]
        expiry_raw = line2_for_checks[8:14]
        expiry_check = line2_for_checks[14]
        nationality = line2[15:18]
        composite_raw = line1_for_checks[5:30] + line2_for_checks[0:7] + line2_for_checks[8:15] + line2_for_checks[18:29]
        composite_check = self._normalize_check_char(line2[29])

        surname, given_names = self._parse_name_field(line3)

        checks = {
            "document_number": self._compute_check(data=doc_number, check_char=doc_number_check),
            "date_of_birth": self._compute_check(data=birth_raw, check_char=birth_check),
            "expiry_date": self._compute_check(data=expiry_raw, check_char=expiry_check),
            "composite": self._compute_check(data=composite_raw, check_char=composite_check),
        }

        parsed_fields = {
            "document_number": self._clean_field(doc_number),
            "date_of_birth": self._parse_mrz_date(birth_raw, prefer_past=True),
            "expiry_date": self._parse_mrz_date(expiry_raw, prefer_past=False),
            "country": self._clean_field(line1[2:5]),
            "nationality": self._clean_field(nationality),
            "sex": self._clean_field(sex),
            "last_name": surname,
            "first_name": given_names,
            "full_name": f"{given_names} {surname}".strip(),
        }

        return {
            "format": "TD1",
            "parsed_fields": parsed_fields,
            "checksums": checks,
        }

    def _compute_check(self, *, data: str, check_char: str) -> Dict[str, Optional[Any]]:
        normalized_check_char = self._normalize_check_char(check_char)

        if not normalized_check_char or not normalized_check_char.isdigit():
            return {
                "available": False,
                "expected": normalized_check_char,
                "computed": None,
                "valid": None,
            }

        computed = self._check_digit(data)
        return {
            "available": True,
            "expected": normalized_check_char,
            "computed": computed,
            "valid": computed == normalized_check_char,
        }

    def _check_digit(self, value: str) -> str:
        total = 0
        for idx, char in enumerate(value):
            char_value = self._mrz_char_value(char)
            total += char_value * self.WEIGHTS[idx % 3]
        return str(total % 10)

    @staticmethod
    def _mrz_char_value(char: str) -> int:
        if char == "<":
            return 0
        if char.isdigit():
            return int(char)
        if "A" <= char <= "Z":
            return ord(char) - ord("A") + 10
        return 0

    def _fix_numeric(self, value: str) -> str:
        return "".join(self.OCR_NUMERIC_MAP.get(char, char) for char in (value or ""))

    def _normalize_check_char(self, value: str) -> str:
        if not value:
            return value
        return self.OCR_NUMERIC_MAP.get(value, value)

    def _normalize_td3_numeric_fields(self, line2: str) -> str:
        normalized = line2
        normalized = self._replace_segment(normalized, 9, 10, self._normalize_check_char(normalized[9]))
        normalized = self._replace_segment(normalized, 13, 19, self._fix_numeric(normalized[13:19]))
        normalized = self._replace_segment(normalized, 19, 20, self._normalize_check_char(normalized[19]))
        normalized = self._replace_segment(normalized, 21, 27, self._fix_numeric(normalized[21:27]))
        normalized = self._replace_segment(normalized, 27, 28, self._normalize_check_char(normalized[27]))
        normalized = self._replace_segment(normalized, 42, 43, self._normalize_check_char(normalized[42]))
        normalized = self._replace_segment(normalized, 43, 44, self._normalize_check_char(normalized[43]))
        return normalized

    def _normalize_td1_line1_numeric_fields(self, line1: str) -> str:
        normalized = line1
        normalized = self._replace_segment(normalized, 14, 15, self._normalize_check_char(normalized[14]))
        return normalized

    def _normalize_td1_line2_numeric_fields(self, line2: str) -> str:
        normalized = line2
        normalized = self._replace_segment(normalized, 0, 6, self._fix_numeric(normalized[0:6]))
        normalized = self._replace_segment(normalized, 6, 7, self._normalize_check_char(normalized[6]))
        normalized = self._replace_segment(normalized, 8, 14, self._fix_numeric(normalized[8:14]))
        normalized = self._replace_segment(normalized, 14, 15, self._normalize_check_char(normalized[14]))
        normalized = self._replace_segment(normalized, 29, 30, self._normalize_check_char(normalized[29]))
        return normalized

    @staticmethod
    def _replace_segment(value: str, start: int, end: int, replacement: str) -> str:
        return value[:start] + replacement + value[end:]

    @staticmethod
    def _fit_mrz_line_length(line: str, target_length: int) -> str:
        """Ajuste la longueur en supprimant d'abord des fillers '<' excedentaires."""

        fitted = line or ""
        while len(fitted) > target_length:
            filler_index = fitted.rfind("<")
            if filler_index == -1:
                fitted = fitted[:target_length]
                break
            fitted = fitted[:filler_index] + fitted[filler_index + 1 :]

        if len(fitted) < target_length:
            fitted = fitted + "<" * (target_length - len(fitted))

        return fitted

    @staticmethod
    def _sanitize_line(line: str) -> str:
        text = (line or "").upper()
        text = text.replace("<<", "<<")
        for marker in ("«", "‹", "﹤", "《", "⟨", "⟩"):
            text = text.replace(marker, "<")

        text = re.sub(r"[\s\-_=|/]+", "<", text)
        cleaned = re.sub(r"[^A-Z0-9<]", "", text)
        return cleaned.strip()

    @staticmethod
    def _clean_field(value: str) -> str:
        return value.replace("<", "").strip()

    @classmethod
    def _parse_name_field(cls, raw: str) -> Tuple[str, str]:
        normalized = raw.strip("<")
        if "<<" in normalized:
            last_name, first_name = normalized.split("<<", 1)
        else:
            parts = normalized.split("<")
            last_name = parts[0] if parts else ""
            first_name = "<".join(parts[1:]) if len(parts) > 1 else ""

        surname = cls._clean_name(last_name)
        given_names = cls._clean_name(first_name)
        return surname, given_names

    @staticmethod
    def _clean_name(value: str) -> str:
        return re.sub(r"\s+", " ", value.replace("<", " ")).strip()

    @classmethod
    def _parse_mrz_date(cls, value: str, *, prefer_past: bool) -> Optional[str]:
        value = "".join(cls.OCR_NUMERIC_MAP.get(char, char) for char in (value or ""))

        if not value or len(value) != 6 or not value.isdigit():
            return None

        yy = int(value[0:2])
        mm = int(value[2:4])
        dd = int(value[4:6])

        now = datetime.now()
        current_yy = now.year % 100

        if prefer_past:
            year = 1900 + yy if yy > current_yy else 2000 + yy
        else:
            year = 2000 + yy

        try:
            return datetime(year, mm, dd).date().isoformat()
        except ValueError:
            return None

    @staticmethod
    def _empty_check() -> Dict[str, Optional[Any]]:
        return {
            "available": False,
            "expected": None,
            "computed": None,
            "valid": None,
        }
