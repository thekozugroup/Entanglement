#!/usr/bin/env python3
"""Translate an Entanglement distributed Rust test report to JUnit XML."""

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re
from tempfile import NamedTemporaryFile
import xml.etree.ElementTree as ET


STATUSES = {"passed", "flaky", "failed", "error", "ignored"}
INVALID_XML = re.compile(r"[^\x09\x0a\x0d\x20-\ud7ff\ue000-\ufffd\U00010000-\U0010ffff]")


def xml_text(value):
    return INVALID_XML.sub(lambda match: ascii(match[0])[1:-1], value)


def finalize(element, source, counts):
    reported = source["counts"]
    if (set(reported) != STATUSES
            or any(type(reported[key]) is not int or reported[key] != counts[key] for key in STATUSES)):
        raise ValueError("reported counts disagree with the test cases")
    elapsed = source["elapsed_ms"]
    if type(elapsed) is not int or elapsed < 0:
        raise ValueError("expected a nonnegative integer elapsed_ms")
    element.attrib.update(tests=str(sum(counts.values())), failures=str(counts["failed"]),
                          errors=str(counts["error"]), skipped=str(counts["ignored"]),
                          time=f"{elapsed // 1000}.{elapsed % 1000:03d}")


def add_case(suite, record):
    name, status, attempts = record["name"], record["status"], record["attempts"]
    if not isinstance(name, str) or not name or status not in STATUSES or not isinstance(attempts, list):
        raise ValueError("invalid test case name, status, or attempts")
    if not attempts and status != "ignored":
        raise ValueError(f"{name}: missing test attempts")
    for index, attempt in enumerate(attempts, 1):
        if (type(attempt["attempt"]) is not int or attempt["attempt"] != index
                or not isinstance(attempt["peer"], str) or not attempt["peer"]
                or attempt["status"] not in {"passed", "failed", "ignored", "error"}):
            raise ValueError(f"{name}: invalid attempt {index}")
        if attempt["status"] != "error" or "exit_code" in attempt:
            if (not isinstance(attempt["stdout"], str) or not isinstance(attempt["stderr"], str)
                    or (attempt["exit_code"] is not None and type(attempt["exit_code"]) is not int)):
                raise ValueError(f"{name}: invalid captured output in attempt {index}")
        if attempt["status"] == "error" and not isinstance(attempt.get("error"), str):
            raise ValueError(f"{name}: missing error diagnostic in attempt {index}")
    if status in {"passed", "flaky"}:
        if attempts[-1]["status"] != "passed" or (
            any(a["status"] == "failed" for a in attempts[:-1]) != (status == "flaky")
        ):
            raise ValueError(f"{name}: successful result disagrees with attempt history")
    if status == "ignored" and attempts and (
        len(attempts) != 1 or attempts[0]["status"] != "ignored"
    ):
        raise ValueError(f"{name}: ignored result disagrees with attempt history")

    case = ET.SubElement(suite, "testcase", classname=suite.get("name"), name=xml_text(name))
    if status == "ignored":
        ET.SubElement(case, "skipped", message="ignored by Rust libtest")
    elif status in {"failed", "error"}:
        detail = next((a for a in reversed(attempts) if a["status"] == status), None)
        if detail is None:
            raise ValueError(f"{name}: no attempt with final status {status}")
        message = detail.get("error") or detail.get("stderr") or f"libtest {status}"
        if not isinstance(message, str):
            raise ValueError(f"{name}: invalid diagnostic")
        child = ET.SubElement(case, "failure" if status == "failed" else "error")
        child.set("message", xml_text(message.strip().splitlines()[0] if message.strip() else status))
    # JSON preserves both output streams, peer IDs and attempt order even when
    # the guest emitted characters which XML 1.0 cannot represent directly.
    ET.SubElement(case, "system-out").text = json.dumps(
        {"status": status, "attempts": attempts}, ensure_ascii=True, separators=(",", ":")
    )


def convert(report):
    root = ET.Element("testsuites")
    totals = Counter()
    if not isinstance(report["suites"], list) or not report["suites"]:
        raise ValueError("expected at least one suite")
    seen_suites = set()
    for source in report["suites"]:
        if not isinstance(source["suite"], str) or not source["suite"] or not isinstance(source["results"], list):
            raise ValueError("invalid suite name or results")
        if source["suite"] in seen_suites:
            raise ValueError(f"duplicate test suite: {source['suite']}")
        seen_suites.add(source["suite"])
        suite = ET.SubElement(root, "testsuite", name=xml_text(source["suite"]))
        if "suite_identity" in source:
            properties = ET.SubElement(suite, "properties")
            for key in ("artifact_blake3", "manifest_blake3"):
                digest = source["suite_identity"][key]
                if not isinstance(digest, str) or not re.fullmatch("[0-9a-f]{64}", digest):
                    raise ValueError(f"invalid suite identity field {key}")
                ET.SubElement(properties, "property", name=key, value=digest)
        counts = Counter()
        seen_names = set()
        for record in source["results"]:
            add_case(suite, record)
            if record["name"] in seen_names:
                raise ValueError(f"duplicate test case: {record['name']}")
            seen_names.add(record["name"])
            counts[record["status"]] += 1
        finalize(suite, source, counts)
        totals.update(counts)
    finalize(root, report, totals)
    ET.indent(root)
    return ET.ElementTree(root)


def write_report(report, output):
    tree = convert(report)
    scratch = NamedTemporaryFile(dir=output.parent, delete=False)
    temp = Path(scratch.name)
    try:
        with scratch:
            tree.write(scratch, encoding="utf-8", xml_declaration=True)
        os.replace(temp, output)
    finally:
        temp.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="JSON from run-rust-tests.py")
    parser.add_argument("output", type=Path, help="destination JUnit XML file")
    args = parser.parse_args()
    try:
        if args.output.exists() and args.report.samefile(args.output):
            raise ValueError("input and output must be different files")
        with args.report.open(encoding="utf-8") as source:
            report = json.load(source)
        write_report(report, args.output)
    except (OSError, KeyError, TypeError, ValueError) as exc:
        parser.exit(1, f"Cannot convert Rust test report: {exc}\n")


if __name__ == "__main__":
    main()
