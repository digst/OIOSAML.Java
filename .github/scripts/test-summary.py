#!/usr/bin/env python3
"""Summarise Maven Surefire test reports as GitHub-flavoured Markdown.

Reads every ``TEST-*.xml`` under ``**/target/surefire-reports/`` (relative to the
current working directory) and writes a Markdown summary to stdout, intended to be
appended to ``$GITHUB_STEP_SUMMARY``. Uses only the Python standard library so the
CI pipeline needs no third-party actions or dependencies.

Exit code is always 0: this reports results, it does not gate the build (the Maven
step already fails the job on test failures).
"""

import glob
import os
import xml.etree.ElementTree as ET


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def iter_testsuites(root):
    # A Surefire per-suite file has a <testsuite> root; a <testsuites> aggregate
    # wraps several. Handle both.
    if root.tag == "testsuites":
        yield from root.findall("testsuite")
    elif root.tag == "testsuite":
        yield root


def main():
    report_files = sorted(glob.glob("**/target/surefire-reports/TEST-*.xml", recursive=True))

    suites = []
    failures = []  # (suite_name, testcase_name, kind, message)
    totals = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0, "time": 0.0}

    for path in report_files:
        try:
            root = ET.parse(path).getroot()
        except ET.ParseError as exc:
            print(f"> [!WARNING]\n> Could not parse `{path}`: {exc}\n")
            continue

        for suite in iter_testsuites(root):
            name = suite.get("name", os.path.basename(path))
            tests = _int(suite.get("tests"))
            fails = _int(suite.get("failures"))
            errs = _int(suite.get("errors"))
            skipped = _int(suite.get("skipped"))
            time = _float(suite.get("time"))

            suites.append((name, tests, fails, errs, skipped, time))
            totals["tests"] += tests
            totals["failures"] += fails
            totals["errors"] += errs
            totals["skipped"] += skipped
            totals["time"] += time

            for case in suite.findall("testcase"):
                for kind in ("failure", "error"):
                    node = case.find(kind)
                    if node is not None:
                        classname = case.get("classname", name)
                        casename = case.get("name", "?")
                        message = (node.get("message") or "").strip().replace("\n", " ")
                        if len(message) > 300:
                            message = message[:297] + "..."
                        failures.append((f"{classname}.{casename}", kind, message))

    print("## Test results\n")

    if not report_files:
        print("> [!WARNING]\n> No Surefire reports were found. Did the tests run?")
        return

    failed_total = totals["failures"] + totals["errors"]
    status = "✅ **All tests passed**" if failed_total == 0 else f"❌ **{failed_total} test(s) failed**"
    print(
        f"{status} — {totals['tests']} run, {totals['failures']} failures, "
        f"{totals['errors']} errors, {totals['skipped']} skipped "
        f"({totals['time']:.1f}s)\n"
    )

    print("| Suite | Tests | Failures | Errors | Skipped | Time (s) |")
    print("|-------|------:|---------:|-------:|--------:|---------:|")
    for name, tests, fails, errs, skipped, time in suites:
        print(f"| {name} | {tests} | {fails} | {errs} | {skipped} | {time:.1f} |")
    print(
        f"| **Total** | **{totals['tests']}** | **{totals['failures']}** | "
        f"**{totals['errors']}** | **{totals['skipped']}** | **{totals['time']:.1f}** |\n"
    )

    if failures:
        print("### Failed tests\n")
        for testcase, kind, message in failures:
            suffix = f" — {message}" if message else ""
            print(f"- **{testcase}** ({kind}){suffix}")


if __name__ == "__main__":
    main()
