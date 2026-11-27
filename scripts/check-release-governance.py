#!/usr/bin/env python3
"""Check the committed maintainer roster and rotation review before release."""

import argparse
from datetime import date, datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib


# Primary crate ownership from the maintainer handbooks and architecture §12.1.
ROLE_CRATES = {
    "core-runtime-lead": {
        "entangle-core", "entangle-runtime", "entangle-broker", "entangle-host", "entangle-types", "entangle-ipc",
    },
    "mesh-lead": {
        "entangle-mesh-local", "entangle-mesh-iroh", "entangle-mesh-tailscale", "entangle-pairing", "entangle-peers",
    },
    "agent-lead": {"entangle-agent-host"},
    "security-lead": {"entangle-signing", "entangle-biscuits"},
    "release-lead": {
        "entangle-manifest", "entangle-oci", "entangle-bin", "entangle-cli", "cargo-entangle",
    },
}


def codeowners_rules(path):
    rules = []
    for line in path.read_text().splitlines():
        fields = line.partition("#")[0].split()
        if not fields:
            continue
        pattern, *owners = fields
        anchored = pattern.startswith("/") or "/" in pattern.rstrip("/")
        glob = re.escape(pattern.removeprefix("/"))
        glob = (
            glob.replace(r"\*\*/", "(?:.*/)?")
            .replace(r"\*\*", ".*")
            .replace(r"\*", "[^/]*")
            .replace(r"\?", "[^/]")
        )
        prefix = "^" if anchored else r"(?:^|/)"
        suffix = "" if pattern.endswith("/") else r"(?=$|/)"
        rules.append((re.compile(prefix + glob + suffix), {user.lower() for user in owners}))
    return rules


def owned_by(rules, path, holder):
    for rule, owners in reversed(rules):
        if rule.search(path):
            return f"@{holder}" in owners
    return False


def rotation_holders(path, today):
    if not path.is_file():
        raise ValueError(f"{path} is missing (architecture §12.1)")
    parts = re.split(r"^## \[?(\d{4}-\d{2}-\d{2})\]?[^\n]*\n", path.read_text(), flags=re.M)
    if len(parts) < 3:
        raise ValueError(f"{path} needs a dated review heading such as `## YYYY-MM-DD`")
    notes = [(date.fromisoformat(day), body) for day, body in zip(parts[1::2], parts[2::2])]
    reviewed, note = max(notes, key=lambda entry: entry[0])
    if not timedelta(0) <= today - reviewed <= timedelta(days=35):
        raise ValueError(f"{path}: review date {reviewed} must be within the past 35 days")

    holders = {}
    for role in ROLE_CRATES:
        listed = re.search(rf"^- {role}:[ \t]*([^\n]+)", note, flags=re.M)
        holders[role] = set(re.findall(r"@([A-Za-z0-9-]+)", listed[1].lower())) if listed else set()
    return holders


def github_api(*args):
    data = subprocess.check_output(["gh", "api", *args], encoding="utf-8")
    if "--paginate" not in args:
        return json.loads(data)
    # `gh api --paginate` writes consecutive JSON values. Decode each page
    # without relying on the newer --slurp option.
    pages = []
    decoder = json.JSONDecoder()
    while data := data.lstrip():
        page, consumed = decoder.raw_decode(data)
        pages.append(page)
        data = data[consumed:]
    return pages


def release_contains(commit):
    exists = subprocess.run(
        ["git", "cat-file", "-e", f"{commit}^{{commit}}"], stderr=subprocess.DEVNULL
    )
    if exists.returncode:
        return False
    ancestry = subprocess.run(["git", "merge-base", "--is-ancestor", commit, "HEAD"])
    if ancestry.returncode > 1:
        ancestry.check_returncode()
    return ancestry.returncode == 0


def recent_merges(repo, holders, since, now):
    query = f"repo:{repo} is:pr is:merged merged:>={since.date().isoformat()}"
    pages = github_api(
        "--method", "GET", "search/issues", "--paginate", "-f", f"q={query}", "-f", "per_page=100"
    )
    for page in pages:
        if page["incomplete_results"] or page["total_count"] > 1000:
            raise ValueError("GitHub returned incomplete merge history")
        for result in page["items"]:
            pr = f"repos/{repo}/pulls/{result['number']}"
            detail = github_api(pr)
            holder = (detail.get("merged_by") or {}).get("login", "").lower()
            if holder not in holders or not detail.get("merged_at"):
                continue
            merged_at = datetime.fromisoformat(detail["merged_at"])
            if not since <= merged_at <= now or not release_contains(detail["merge_commit_sha"]):
                continue
            if detail["changed_files"] > 3000:
                raise ValueError(f"PR #{result['number']} exceeds GitHub's changed-file API limit")
            files = github_api(f"{pr}/files?per_page=100", "--paginate")
            yield holder, [item["filename"] for page in files for item in page]


def check(bus_factor_only):
    now = datetime.now(timezone.utc)
    roster = tomllib.loads(Path("docs/maintainers/roles.toml").read_text()).get("role", {})
    holders = {
        role: {name.lower() for name in roster.get(role, {}).get("holders", [])}
        for role in ROLE_CRATES
    }
    errors = [
        f"{role} needs two named holders (found {len(names)})"
        for role, names in holders.items()
        if len(names) < 2
    ]
    rotation = None
    if not bus_factor_only:
        try:
            rotation = rotation_holders(Path("docs/governance/rotations.md"), now.date())
        except ValueError as error:
            errors.append(str(error))
        if rotation is not None:
            for role, reviewed in rotation.items():
                holders[role] &= reviewed
                if len(holders[role]) < 2:
                    errors.append(
                        f"{role} needs two roster holders in the latest rotation review "
                        f"(`- {role}: @holder, @holder`)"
                    )
    if errors:
        return errors

    repo = os.environ["GITHUB_REPOSITORY"]
    owners = codeowners_rules(Path(".github/CODEOWNERS"))
    active = {role: set() for role in ROLE_CRATES}
    for holder, files in recent_merges(repo, set.union(*holders.values()), now - timedelta(days=60), now):
        for path in files:
            parts = path.split("/", 2)
            if len(parts) != 3 or parts[0] != "crates":
                continue
            if not owned_by(owners, path, holder):
                continue
            crate = parts[1]
            for role, crates in ROLE_CRATES.items():
                if holder in holders[role] and crate in crates:
                    active[role].add(holder)
    return [
        f"{role} needs two holders with an owned crate merge in the past 60 days (found {len(names)})"
        for role, names in active.items()
        if len(names) < 2
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--bus-factor-only", action="store_true", help="check merge activity without the release rotation review"
    )
    try:
        errors = check(parser.parse_args().bus_factor_only)
    except (OSError, KeyError, ValueError, subprocess.CalledProcessError) as error:
        errors = [str(error)]
    if errors:
        print("Release governance check failed", *errors, sep="\n- ", file=sys.stderr)
        return 1
    print("Release governance check passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
