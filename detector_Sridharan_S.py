#!/usr/bin/env python3
"""
Author : Sridharan  S

"""

import sys
import csv
import json
import re


PHONE_RE    = re.compile(r"^[6-9]\d{9}$")               # Indian 10-digit mobile
AADHAR_RE   = re.compile(r"^\d{4}\s?\d{4}\s?\d{4}$")    # 12-digit Aadhar (with/without spaces)
PASSPORT_RE = re.compile(r"^[A-PR-WYa-pr-wy][0-9]{7}$") # Passport (e.g., P1234567)
UPI_RE      = re.compile(r"^[\w.\-]{2,}@[\w]{2,}$")     # UPI ID: user@bank
EMAIL_RE    = re.compile(r"^[\w\.\-]+@[A-Za-z0-9\-]+\.[A-Za-z]{2,}$")
PIN_RE      = re.compile(r"\b\d{6}\b")
IP_RE       = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def mask_phone(value: str) -> str:
    return str(value)[:2] + "XXXXXX" + str(value)[-2:]

def mask_aadhar(value: str) -> str:
    return "XXXX XXXX " + str(value)[-4:]

def mask_passport(value: str) -> str:
    return str(value)[0] + "XXXXXXX"

def mask_upi(value: str) -> str:
    if "@" in value:
        user, bank = value.split("@", 1)
        return user[:2] + "***@" + bank
    return "[REDACTED_PII]"

def mask_email(value: str) -> str:
    if "@" in value:
        local, domain = value.split("@", 1)
        return local[:2] + "***@" + domain
    return "[REDACTED_PII]"

def mask_name(value: str) -> str:
    return " ".join([part[0] + "XXX" for part in str(value).split()])




def redact_record(record: dict):
    found = {
        "phone": False, "aadhar": False, "passport": False, "upi": False,
        "email": False, "name_full": False, "address": False, "device_ip": False
    }

    # Standalone checks
    if "phone" in record and PHONE_RE.fullmatch(str(record["phone"])):
        record["phone"] = mask_phone(record["phone"])
        found["phone"] = True

    if "aadhar" in record and AADHAR_RE.fullmatch(str(record["aadhar"])):
        record["aadhar"] = mask_aadhar(record["aadhar"])
        found["aadhar"] = True

    if "passport" in record and PASSPORT_RE.fullmatch(str(record["passport"])):
        record["passport"] = mask_passport(record["passport"])
        found["passport"] = True

    if "upi_id" in record and UPI_RE.fullmatch(str(record["upi_id"])):
        record["upi_id"] = mask_upi(record["upi_id"])
        found["upi"] = True

    # Combinatorial checks
    if "email" in record and EMAIL_RE.fullmatch(str(record["email"])):
        found["email"] = True

    if "name" in record and len(str(record["name"]).split()) >= 2:
        found["name_full"] = True

    if "address" in record:
        addr = str(record["address"]).lower()
        if PIN_RE.search(addr) or any(w in addr for w in ["road", "street", "lane", "nagar", "block"]):
            found["address"] = True

    if ("ip_address" in record and IP_RE.fullmatch(str(record["ip_address"]))) \
       or ("device_id" in record and record["device_id"]):
        found["device_ip"] = True

    # Decide if this record contains PII
    device_tied = found["device_ip"] and (found["email"] or found["name_full"] or found["phone"])
    standalone  = found["phone"] or found["aadhar"] or found["passport"] or found["upi"]
    combinatorial = sum([found["email"], found["name_full"], found["address"]]) >= 2 or device_tied
    is_pii = bool(standalone or combinatorial)

    # Apply masking if PII
    if is_pii:
        if found["email"]:
            record["email"] = mask_email(record["email"])
        if found["name_full"]:
            record["name"] = mask_name(record["name"])
        if found["address"]:
            record["address"] = "[REDACTED_PII]"
        if found["device_ip"]:
            if "ip_address" in record:
                record["ip_address"] = "[REDACTED_PII]"
            if "device_id" in record:
                record["device_id"] = "[REDACTED_PII]"

    return record, is_pii




def main():
    if len(sys.argv) < 2:
        print("Usage: python3 detector_Sridharan_S.py input.csv [output.csv]")
        sys.exit(1)

    inp = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else "redacted_output_Sridharan_S.csv"

    with open(inp, newline='', encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    output = []
    for row in rows:
        raw_json = row.get("Data_json") or row.get("data_json") or "{}"
        try:
            data = json.loads(raw_json)
        except Exception:
            data = {}

        redacted, is_pii = redact_record(data)

        output.append({
            "record_id": row.get("record_id", ""),
            "redacted_data_json": json.dumps(redacted, ensure_ascii=False),
            "is_pii": str(is_pii)
        })

    with open(out, "w", newline='', encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["record_id", "redacted_data_json", "is_pii"])
        writer.writeheader()
        writer.writerows(output)

    print(f"Wrote {out}")

if __name__ == "__main__":
    main()

