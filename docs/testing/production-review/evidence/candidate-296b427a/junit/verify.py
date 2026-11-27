"""Independently compare Entanglement JSON with a standard JUnit consumer."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import gzip
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

from junitparser import Error, Failure, JUnitXml, Skipped


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_reports(node):
    if isinstance(node, dict):
        if isinstance(node.get("suites"), list) and "elapsed_ms" in node and "counts" in node:
            yield node
        elif (isinstance(node.get("command"), list) and any(Path(arg).name == "run-rust-tests.py" for arg in node["command"] if isinstance(arg, str)) and node.get("stdout")):
            yield from read_reports(json.loads(node["stdout"]))
        else:
            for item in node.values():
                yield from read_reports(item)
    elif isinstance(node, list):
        for item in node:
            yield from read_reports(item)


def verify(script, directory, report):
    source, target = directory / "input.json", directory / "report.xml"
    source.write_text(json.dumps(report))
    subprocess.run([sys.executable, script, source, target], check=True)
    dom = ET.parse(target).getroot()
    parsed = JUnitXml.fromfile(str(target))
    counts = Counter()
    assert len(parsed) == len(report["suites"])
    for expected, suite in zip(report["suites"], parsed):
        assert suite.name == expected["suite"]
        assert abs(suite.time * 1000 - expected["elapsed_ms"]) < .001
        assert suite.tests == len(expected["results"])
        assert (suite.failures, suite.errors, suite.skipped) == tuple(expected["counts"][s] for s in ("failed", "error", "ignored"))
        if "suite_identity" in expected:
            assert {p.name:p.value for p in suite.properties()} == expected["suite_identity"]
        for record, case in zip(expected["results"], suite):
            assert (case.classname,case.name) == (expected["suite"],record["name"])
            status = record["status"]
            assert [type(item) for item in case.result] == {"error":[Error], "failed":[Failure], "ignored":[Skipped]}.get(status, [])
            assert json.loads(case.system_out) == {"status":status,"attempts":record["attempts"]}
            counts[status] += 1
    assert dom.tag == "testsuites" and int(dom.get("tests")) == sum(counts.values())
    assert abs(float(dom.get("time"))*1000 - report["elapsed_ms"]) < .001
    return dict(counts=dict(counts), cases=sum(counts.values()), input_bytes=source.stat().st_size,
                input_sha256=digest(source), xml_bytes=target.stat().st_size, xml_sha256=digest(target))


def main():
    a = argparse.ArgumentParser(description=__doc__)
    a.add_argument("--script", type=Path, required=True)
    a.add_argument("--result", type=Path, required=True)
    a.add_argument("reports", type=Path, nargs="+")
    args=a.parse_args()
    output=dict(started=datetime.now(timezone.utc).isoformat(),
                converter_sha256=digest(args.script), consumer="junitparser",version=version("junitparser"),
                python=sys.version.split()[0],inputs=[])
    with tempfile.TemporaryDirectory() as temp:
        directory = Path(temp)
        for path in args.reports:
            data=path.read_bytes()
            if path.suffix == ".gz":
                data=gzip.decompress(data)
            measures=[verify(args.script, directory, r) for r in read_reports(json.loads(data))]
            assert measures, path
            output["inputs"].append(dict(name=path.name, sha256=digest(path), results=measures))
    output["finished"]=datetime.now(timezone.utc).isoformat()
    args.result.write_text(json.dumps(output, indent=2)+"\n")
    print("JUnit inputs verified:", [(r["name"],len(r["results"]),sum(t["cases"] for t in r["results"])) for r in output["inputs"]])


if __name__ == "__main__":
    main()
