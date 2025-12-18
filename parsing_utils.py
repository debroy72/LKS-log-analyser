import re
from datetime import datetime
import pandas as pd

TAG_MAP = {
    "Loaded": "Gestartet",
    "BOOT": "Progammstart",
    "MAC": "Progammstart",
    "WO": "Fenster wird geöffnet",
    "WC": "Fenster wird geschlossen",
    "MB": "Text in Message-Box",
    "ML": "Meldung",
    "LOAD_PLU": "PLU laden",
    "DRV": "Drucker-Status",
    "PL": "Etikett drucken",
    "Scanner": "Scanner",
    "FtpAuthenticateEx": "FTP-Verbindung wurde aufgebaut",
    "Connection established": "TCP Verbindung wurde aufgebaut",
    "Full-Access-Benutzer Login": "Anmeldung an PAW",
    "L_MouseClick": "Linke Maustaste",
    "** UE": "Unhandled exception",
    "**": "Exception",
    "DE=": "DoEvent Bandstopp ausgelöst",
    "FU=0": "Frequenzumrichter einschalten",
    "FU=1": "Frequenzumrichter ausschalten",
    "RI": "RI-Befehl empfangen",
    "SZ": "Summenzähler",
    "TS": "Timestamp",
    "Close": "Close",
    "Etikett oder Spalt zu lang": "Etikett oder Spalt zu lang",
    "Druckleiste ist abgehoben": "Druckleiste ist abgehoben",
    "Write XML-Report": "Schreibe XML-FPVO Report",
    "ZI": "Start Init Zelle",
    "ZO": "End init Zelle",
    "NT_F": "Nullstellung fehlerhaft",
    "TB": "Befehl wurde an die Taktbandsteuerung gesendet",
    "saveTC": "saveTC --> Command for SaveTotalCounters",
}
ORDERED_TAGS = sorted(TAG_MAP.keys(), key=len, reverse=True)
PAW_LINE_PATTERN = re.compile(r"(?P<pawts>\d{2}_\d{2}_\d{2}[-–]\d{2}:\d{2}:\d{2})\s*(?P<payload>.*)")

KEY_CODE_DEFINITIONS = [
    ("0x13b", "F1"),
    ("0x13c", "F2"),
    ("0x13d", "F3"),
    ("0x13e", "F4"),
    ("0x13f", "F5"),
    ("0x140", "F6"),
    ("0x141", "F7"),
    ("0x142", "F8"),
    ("0x143", "F9"),
    ("0x144", "F10"),
    ("0x185", "F11"),
    ("0x186", "F12"),
    ("0x148", "CUR_UP"),
    ("0x150", "CUR_DWN"),
    ("0x14b", "CUR_LEFT"),
    ("0x14d", "CUR_RIGHT"),
    ("0x147", "HOME"),
    ("0x14f", "END"),
    ("0x149", "PAGE_UP"),
    ("0x151", "PAGE_DWN"),
    ("0x152", "INS"),
    ("0x153", "DEL"),
    ("404", "CTRL_TAB"),
    ("397", "CTRL_UP"),
    ("401", "CTRL_DWN"),
    ("371", "CTRL_LEFT"),
    ("372", "CTRL_RIGHT"),
    ("0x11e", "ALT_A Short-Cut für Hall of Fame"),
    ("0x110", "ALT_Q Short-Cut für Softkey ( zum Drucken )"),
    ("0x119", "ALT_P Short-Cut für Password"),
    ("0x120", "ALT_D Short-Cut Root erhält Focus"),
    ("0x123", "ALT_H Short-Cut für Hardcopy"),
    ("0x117", "ALT_I Switch to isolated arabic character"),
    ("0x125", "ALT_K Toggle Keybord-Offset"),
    ("0x111", "ALT_W Short-Cut für Hardcopy Window"),
    ("0x12c", "ALT_Z Short-Cut für Hardcopy Screen"),
    ("0x130", "ALT_B Toggle Invers-Mode"),
    ("0x12e", "ALT_C"),
    ("0x112", "ALT_E"),
    ("0x121", "ALT_F"),
    ("0x122", "ALT_G"),
    ("0x12d", "ALT_X"),
    ("0x131", "ALT_N"),
    ("0x126", "ALT_L"),
    ("0x113", "ALT_R"),
    ("0x11f", "ALT_S"),
    ("0x135", "ALT_SH"),
    ("0x116", "ALT_U"),
    ("0x16e", "ALT_F7"),
    ("1", "CTRL_A"),
    ("2", "CTRL_B"),
    ("3", "CTRL_C"),
    ("4", "CTRL_D"),
    ("5", "CTRL_E"),
    ("6", "CTRL_F"),
    ("7", "CTRL_G Bell"),
    ("8", "CTRL_H Backspace"),
    ("9", "CTRL_I Tab"),
    ("10", "CTRL_J"),
    ("11", "CTRL_K"),
    ("12", "CTRL_L"),
    ("13", "CTRL_M"),
    ("14", "CTRL_N"),
    ("15", "CTRL_O"),
    ("16", "CTRL_P"),
    ("17", "CTRL_Q"),
    ("18", "CTRL_R"),
    ("19", "CTRL_S"),
    ("20", "CTRL_T"),
    ("21", "CTRL_U"),
    ("22", "CTRL_V"),
    ("23", "CTRL_W"),
    ("24", "CTRL_X"),
    ("25", "CTRL_Y"),
    ("26", "CTRL_Z"),
    ("1001", "SK_CloseWnd"),
    ("1002", "SK_CancelWnd"),
    ("1003", "SK_NextWnd"),
    ("1016", "SK_PrevWnd"),
    ("1004", "SK_NextComp"),
    ("1005", "SK_PrevComp"),
    ("1006", "SK_CurLEFT"),
    ("1007", "SK_CurRIGHT"),
    ("1008", "SK_CurUP"),
    ("1009", "SK_CurDOWN"),
    ("1010", "SK_CurHOME"),
    ("1011", "SK_CurEND"),
    ("1012", "SK_CurBACKSPACE"),
    ("1013", "SK_CurDELETE"),
    ("1014", "SK_ToggleINSERT"),
    ("1015", "SK_CancelInput"),
    ("1017", "SK_PageUP"),
    ("1018", "SK_PageDOWN"),
    ("1019", "SK_Help"),
    ("0x3e9", "SK_CloseWnd"),
    ("0x3ea", "SK_CancelWnd"),
    ("0x3eb", "SK_NextWnd"),
    ("0x3f8", "SK_PrevWnd"),
    ("0x3ec", "SK_NextComp"),
    ("0x3ed", "SK_PrevComp"),
    ("0x3ee", "SK_CurLEFT"),
    ("0x3ef", "SK_CurRIGHT"),
    ("0x3f0", "SK_CurUP"),
    ("0x3f1", "SK_CurDOWN"),
    ("0x3f2", "SK_CurHOME"),
    ("0x3f3", "SK_CurEND"),
    ("0x3f4", "SK_CurBACKSPACE"),
    ("0x3f5", "SK_CurDELETE"),
    ("0x3f6", "SK_ToggleINSERT"),
    ("0x3f7", "SK_CancelInput"),
    ("0x3f9", "SK_PageUP"),
    ("0x3fa", "SK_PageDOWN"),
    ("0x3fb", "SK_Help"),
]

TS_PATTERNS = [
    r"(?P<ts>\d{2}_\d{2}_\d{2}[-–]\d{2}:\d{2}:\d{2})",
    r"(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,3})?)",
    r"(?P<ts>\d{2}\.\d{2}\.\d{4}[ T]\d{2}:\d{2}:\d{2})",
    r"(?P<ts>\d{2}/\d{2}/\d{4}[ T]\d{2}:\d{2}:\d{2})",
]
COMPILED_TS = [re.compile(p) for p in TS_PATTERNS]


def extract_timestamp(s: str):
    for cre in COMPILED_TS:
        m = cre.search(s)
        if m:
            ts = m.group("ts")
            for fmt in (
                "%y_%m_%d-%H:%M:%S",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S.%f",
                "%Y-%m-%dT%H:%M:%S.%f",
                "%d.%m.%Y %H:%M:%S",
                "%d/%m/%Y %H:%M:%S",
            ):
                try:
                    dt = datetime.strptime(ts.replace(",", "."), fmt)
                    return dt.isoformat(sep=" ")
                except ValueError:
                    continue
            return ts
    return ""


def extract_tag(s: str):
    s = s.strip()
    if re.search(r"\*\*\s*UE", s):
        return "** UE"
    if re.search(r"\bMB\s*=", s):
        return "MB"
    if re.search(r"\bLOAD[_\s]*PLU\b", s, flags=re.IGNORECASE):
        return "LOAD_PLU"
    for t in ORDERED_TAGS:
        if t in s:
            return t
    if "DE=" in s:
        return "DE="
    if "FU=0" in s:
        return "FU=0"
    if "FU=1" in s:
        return "FU=1"
    return ""


def extract_message(s: str, tag: str):
    s2 = s
    for cre in COMPILED_TS:
        s2 = cre.sub("", s2, count=1)
    s2 = s2.strip(" :-")

    if tag == "MB":
        s2 = re.sub(r".*?MB\s*=\s*\[[^\]]*\]\s*", "", s2).strip()
    elif tag == "LOAD_PLU":
        s2 = re.sub(r".*?\bLOAD[_\s]*PLU\b", "", s2, flags=re.IGNORECASE).strip()
    elif tag == "** UE":
        s2 = re.sub(r".*?\*\*\s*UE\s*", "", s2).strip()
    elif tag and tag != "saveTC":
        s2 = re.sub(rf"\b{re.escape(tag)}\b", "", s2).strip()
    return s2


def resolve_description(tag: str, payload: str):
    if tag == "saveTC":
        payload_upper = (payload or "").upper()
        if "TCXML" in payload_upper:
            return "saveTC --> Command for SaveTotalCounters as XML"
    return TAG_MAP.get(tag, "")


def _parse_code_value(code_str: str):
    code_str = (code_str or "").strip()
    if not code_str:
        return None
    clean = code_str.lower()
    base = 16 if clean.startswith("0x") or any(c in "abcdef" for c in clean) else 10
    if clean.startswith("0x"):
        clean = clean[2:]
    if not clean:
        return None
    try:
        return int(clean, base)
    except ValueError:
        return None


def _build_keycode_lookup():
    lookup = {}
    for code, label in KEY_CODE_DEFINITIONS:
        value = _parse_code_value(code)
        if value is not None and label:
            lookup.setdefault(value, label)
    return lookup


KEY_CODE_LOOKUP = _build_keycode_lookup()
UNRECOGNIZED_KEY_CODES = set()


def _log_unknown_code(token: str):
    if token and token not in UNRECOGNIZED_KEY_CODES:
        UNRECOGNIZED_KEY_CODES.add(token)
        print(f"[KeyCode] Unknown key code encountered: {token}")


def decode_key_code(payload_text: str):
    token = (payload_text or "").strip()
    if not token:
        return ""
    token = token.strip("[] ").strip()
    token = token.rstrip(";").strip()
    original_token = token
    if not token:
        return ""
    lower = token.lower()
    if lower.startswith("0x"):
        lower = lower[2:]
        hex_hint = True
    else:
        hex_hint = any(c in "abcdef" for c in lower)
    attempt_order = [16, 10] if hex_hint else [10, 16]
    looks_like_code = bool(re.fullmatch(r"(?:0x)?[0-9A-Fa-f]+", original_token))
    for base in attempt_order:
        try:
            value = int(lower, base)
        except ValueError:
            continue
        label = KEY_CODE_LOOKUP.get(value)
        if not label:
            continue
        if base == 16:
            code_display = f"0x{value:X}"
        else:
            code_display = str(value)
        return f"{code_display} : {label}"
    if looks_like_code:
        _log_unknown_code(original_token)
    return ""

HEADER_PATTERNS = {
    "timestamp": re.compile(r"(?i)^time stamp\s*:\s*(.+)$"),
    "sender_id": re.compile(r"(?i)^sender id\s*:\s*(.+)$"),
    "target_id": re.compile(r"(?i)^target id\s*:\s*(.+)$"),
    "driver_name": re.compile(r"(?i)^driver name\s*:\s*(.+)$"),
    "datagram_type": re.compile(r"(?i)^datagram type\s*:\s*(.+)$"),
    "target_encoding": re.compile(r"(?i)^target encoding\s*:\s*(.+)$"),
}


def split_blocks(lines):
    blocks = []
    current = []
    start_line_no = 1
    line_no = 1
    for raw in lines:
        txt = raw.rstrip("\n")
        sep = re.match(r"[-]{5,}", txt)
        if sep:
            if current:
                blocks.append((start_line_no, current))
                current = []
            start_line_no = line_no + 1
        else:
            current.append((line_no, txt))
        line_no += 1
    if current:
        blocks.append((start_line_no, current))
    return blocks


def _collect_paw_entries(non_header_lines):
    """Split PAW body lines into entries, capturing trailing text for each timestamp."""
    entries = []
    current = None

    for ln_no, line in non_header_lines:
        raw_line = line.rstrip("\r")
        stripped = raw_line.strip()

        if not stripped:
            if current is not None:
                current["payload_lines"].append("")
                current["raw_lines"].append("")
            continue

        match = PAW_LINE_PATTERN.match(stripped)
        if match:
            if current is not None:
                entries.append(current)
            current = {
                "line_no": ln_no,
                "paw_ts_raw": match.group("pawts"),
                "payload_lines": [match.group("payload").strip()],
                "reference_line": stripped,
                "raw_lines": [raw_line],
            }
        elif current is not None:
            current["payload_lines"].append(raw_line.strip())
            current["raw_lines"].append(raw_line)

    if current is not None:
        entries.append(current)

    normalized = []
    for entry in entries:
        payload_text = "\n".join(entry["payload_lines"]).strip()
        normalized.append(
            {
                "line_no": entry["line_no"],
                "paw_ts_raw": entry["paw_ts_raw"],
                "payload": payload_text,
                "reference_line": entry["reference_line"],
                "raw_text": "\n".join(entry["raw_lines"]).strip(),
            }
        )
    return normalized


def parse_block(start_line_no, block_lines):
    field_values = {}
    for key, cre in HEADER_PATTERNS.items():
        for _, line in block_lines:
            m = cre.match(line)
            if m:
                field_values[key] = m.group(1).strip()
                break

    header_lines = []
    non_header = []
    for ln_no, txt in block_lines:
        if any(cre.match(txt) for cre in HEADER_PATTERNS.values()):
            header_lines.append(txt)
        else:
            non_header.append((ln_no, txt))

    raw_block = "\n".join(txt for _, txt in block_lines)
    header_text = "\n".join(header_lines).strip()
    driver_name = field_values.get("driver_name", "").strip().lower()

    def build_record(line_no, payload_text, paw_ts_raw, reference_line, raw_text):
        payload_text = (payload_text or "").strip()
        reference_line = reference_line or payload_text
        source_text = payload_text or reference_line
        ts = field_values.get("timestamp") or extract_timestamp(reference_line)
        tag = extract_tag(source_text)
        msg = extract_message(source_text, tag)
        desc = resolve_description(tag, source_text)
        decoded = decode_key_code(payload_text)
        if decoded:
            msg = decoded
            if not desc:
                desc = "Key code"

        return {
            "line_no": line_no or start_line_no,
            "timestamp": ts,
            "tag": tag,
            "description": desc,
            "message": msg,
            "raw": raw_text,
            "sender_id": field_values.get("sender_id", ""),
            "target_id": field_values.get("target_id", ""),
            "driver_name": field_values.get("driver_name", ""),
            "datagram_type": field_values.get("datagram_type", ""),
            "target_encoding": field_values.get("target_encoding", ""),
            "type": "RecordPaw" if field_values else "RecordLks",
            "recordType": desc or "None",
            "paw_ts_raw": paw_ts_raw or "",
            "Content": source_text.strip(" :-"),
        }

    paw_entries = _collect_paw_entries(non_header) if driver_name == "logs" else []
    if paw_entries:
        return [
            build_record(
                entry["line_no"],
                entry["payload"],
                entry["paw_ts_raw"],
                entry["reference_line"],
                f"{header_text}\n\n{entry['raw_text']}".strip() if header_text else entry["raw_text"],
            )
            for entry in paw_entries
        ]

    if non_header:
        message_line_no, message_line = non_header[-1]
    elif block_lines:
        message_line_no, message_line = block_lines[-1]
    else:
        message_line_no, message_line = start_line_no, ""

    paw_ts_raw = ""
    payload = message_line
    match = PAW_LINE_PATTERN.match(message_line.strip())
    if match:
        paw_ts_raw = match.group("pawts")
        payload = match.group("payload").strip()
    else:
        payload = (payload or "").strip()

    return [build_record(message_line_no, payload, paw_ts_raw, message_line, raw_block)]


def parse_lines(lines):
    blocks = split_blocks(lines)
    recs = []
    for start, blines in blocks:
        recs.extend(parse_block(start, blines))
    df = pd.DataFrame(recs)
    if df.empty:
        return df

    df["Content"] = df["Content"].fillna("")
    df["timestamp_dt"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["timestamp_dt"] = df["timestamp_dt"].ffill()
    df["timestamp"] = df["timestamp_dt"].dt.strftime("%Y-%m-%d %H:%M:%S.%f").str[:-3]
    ts_fmt = df["timestamp_dt"].dt.strftime("%d.%m.%Y %H:%M:%S,%f")
    ts_fmt = ts_fmt.fillna("").str[:-3]
    df["time stamp"] = ts_fmt
    df["time"] = ts_fmt

    paw_source = df.get("paw_ts_raw")
    if paw_source is None:
        paw_source = pd.Series("", index=df.index)
    paw_dt = pd.to_datetime(paw_source, errors="coerce")
    paw_fmt = paw_dt.dt.strftime("%d.%m.%Y %H:%M:%S,%f")
    paw_fmt = paw_fmt.fillna("").str[:-3]
    df["PAW timestamp"] = paw_fmt
    df["PAW recordContent"] = df["Content"].where(
        df["Content"].str.startswith("[") & df["Content"].str.endswith("]"),
        "",
    )
    if "paw_ts_raw" in df.columns:
        df = df.drop(columns=["paw_ts_raw"])
    return df


def mask_mb(df: pd.DataFrame):
    return df["tag"].eq("MB") | df["raw"].str.contains(r"\bMB\s*=", na=False)


def build_counts(df: pd.DataFrame):
    counts = {}
    counts["PLU Loads"] = int(((df["tag"] == "LOAD_PLU") | df["raw"].str.contains(r"\bLOAD[_\s]?PLU\b", na=False)).sum())
    counts["MB (any)"] = int(mask_mb(df).sum())
    counts["MB =[]"] = int(df["raw"].str.contains(r"\bMB\s*=\s*\[\s*\]", na=False).sum())
    counts["Unhandled Exceptions (** UE)"] = int(((df["tag"] == "** UE") | df["raw"].str.contains(r"\*\*\s*UE", na=False)).sum())
    mask_other = (
        (df["tag"] == "**")
        | (df["raw"].str.contains(r"\bException\b", na=False))
        | (df["raw"].str.contains(r"\bError\b", na=False, case=False))
    ) & ~df["raw"].str.contains(r"\*\*\s*UE", na=False)
    counts["Other Exceptions/Errors"] = int(mask_other.sum())
    counts["TCP Connections Established"] = int(df["raw"].str.contains(r"Connection established", na=False).sum())
    counts["FTP Connections Established"] = int(df["raw"].str.contains(r"FtpAuthenticateEx", na=False).sum())
    counts["Nullstellung fehlerhaft (NT_F)"] = int(df["raw"].str.contains(r"\bNT_F\b", na=False).sum())
    counts["Etikett oder Spalt zu lang"] = int(df["raw"].str.contains(r"Etikett oder Spalt zu lang", na=False).sum())
    counts["Druckleiste ist abgehoben"] = int(df["raw"].str.contains(r"Druckleiste ist abgehoben", na=False).sum())
    counts["Bandstopp (DE=)"] = int(df["raw"].str.contains(r"\bDE\s*=", na=False).sum())
    counts["Total Events (lines)"] = int(len(df))
    return counts
