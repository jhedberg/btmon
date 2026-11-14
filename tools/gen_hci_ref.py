#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Silicon Laboratories Inc.
"""Make the HCI reference (tools/hci_ref_v<version>.txt) from the Core Specification.

The input is the text of the whole Core Specification PDF as written by
`pdftotext -layout`.  Only Vol 4, Part E, Section 7 (HCI commands and events)
is read.  For every command and event section the output lists:

* the section number and title, and each version's name with its opcode,
  event code or, for LE Meta subevents, event code and subevent code
  (`HCI_LE_Data_Length_Change[v2]=0x3E/0x39`);
* for a command or event with more than one version, the parameters of each
  version as the summary table of the section lists them
  (`Versions:`, command parameters `->` return parameters);
* the "Missing parameters" table of a versioned command;
* the command, return and event parameters with their sizes.

Usage:
    pdftotext -layout Core_v7.0.pdf core.txt
    tools/gen_hci_ref.py core.txt > tools/hci_ref_v7.0.txt
"""
import re
import sys

PAGE_HEADER = re.compile(r"BLUETOOTH CORE SPECIFICATION Version \S+ \| Vol (\d+), Part ([A-Z])\s+Page \d+")
FOOTER = re.compile(r"^\s*Bluetooth SIG Proprietary(\s+Version Date: .*)?\s*$")
RUNNING_TITLES = (
    "Host Controller Interface (HCI) Functional Specification",
    "Host Controller Interface Functional Specification",
)
HEADING = re.compile(r"^(\d+(?:\.\d+)+)\s+(\S.*?)\s*$")
PARAM = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_]*(?:\[[a-z0-9]+\])*)(?: (\[v\d+\]))?:\s+Size:\s*(.+?)\s*$")
PARAM_BLOCKS = ("Command parameters:", "Return parameters:", "Event parameters:")
TABLE_HEADER = re.compile(r"^ ?(Command|Event)\s{2,}(OCF|Event)\b")


def part_e_lines(path):
    """Lines of Vol 4, Part E without page headers, footers and running titles."""
    out = []
    in_part = False
    after_header = False
    for line in open(path, errors="replace"):
        line = line.rstrip().replace("\f", "")
        m = PAGE_HEADER.search(line)
        if m:
            in_part = m.groups() == ("4", "E")
            after_header = True
            continue
        if not in_part or FOOTER.match(line):
            continue
        if after_header:
            if not line.strip():
                continue
            after_header = False
            if line.strip() in RUNNING_TITLES:
                continue
        out.append(line)
    return out


def section_title(num, title):
    """The title of a command or event section of Section 7, or None for other headings.

    A footnote mark after the title is dropped, and a title without "command"
    or "event" gets the word that its subsection implies (7.7 holds the events).
    """
    if not re.match(r"^7\.[1-8]\.\d+", num) or title.startswith("["):
        return None
    kind = "event" if num.startswith("7.7.") else "command"
    title = re.sub(r"\s+", " ", title)
    title = re.sub(r"\b(command|event)\d+$", r"\1", title)
    if not title.endswith(" " + kind):
        title += " " + kind
    return title


def split_sections(lines):
    """(number, title, body lines) of each command and event section."""
    sections = []
    cur = None
    for line in lines:
        if "...." in line:
            continue  # table of contents
        if re.match(r"^Appendix [A-Z]\s{2,}\S", line):
            cur = None
            continue
        m = HEADING.match(line)
        if m and m.group(2)[0].isupper() or m and m.group(2)[0] == "[":
            title = section_title(*m.groups())
            cur = (m.group(1), title, []) if title else None
            if cur:
                sections.append(cur)
            continue
        if cur is not None:
            cur[2].append(line)
    return sections


def block_start(line):
    """The name of the parameter block that starts at this line, or None."""
    if line.startswith(" "):
        return None
    for b in PARAM_BLOCKS:
        if line.strip().lower() == b.lower():
            return b
    return None


def column_kinds(header):
    """(start column, kind) of the cells of a summary table header line."""
    cols = []
    for i, m in enumerate(re.finditer(r"\S+(?: \S+)*", header)):
        text = m.group()
        if i == 0:
            kind = "name"
        elif text in ("OCF", "Event", "Event Code"):
            kind = "code"
        elif text.startswith("Subevent"):
            kind = "subevent"
        elif text.startswith("Return"):
            kind = "return"
        else:
            kind = "params"
        cols.append((m.start(), kind))
    return cols


def join_name(words):
    """An HCI name and version from the words of a name cell that can wrap."""
    name = ""
    version = None
    for w in words:
        m = re.match(r"^\[(v\d+)\]$", w)
        if m:
            version = m.group(1)
        elif name.endswith("-"):
            name = name[:-1] + w
        elif not name or name.endswith("_"):
            name += w
        else:
            name += "_" + w
    return name, version


def param_list(text):
    text = re.sub(r"-\s+", "", text)
    if text.strip().lower() in ("", "none"):
        return []
    return [p.strip() for p in text.split(",") if p.strip()]


def parse_table(body):
    """The rows of the summary table at the start of a section.

    A table can be split over pages, and each version can have a table of its
    own, so the column positions are taken again from every header line.
    """
    rows = []
    cols = None
    after_header = False
    for line in body:
        if line.startswith("Description:") or block_start(line):
            break
        if not line.strip():
            continue
        if TABLE_HEADER.match(line):
            cols = column_kinds(line)
            after_header = True
            continue
        if cols is None:
            if not line.startswith(" "):
                return []  # text before any table
            continue
        if line.strip().startswith("The order of the"):
            break  # a note row spanning the table
        words = [(m.start(), m.group()) for m in re.finditer(r"\S+", line)]
        if after_header and all(w in ("Code", "Parameters") for _, w in words):
            after_header = False
            continue  # second line of a wrapped header
        after_header = False
        cells = {k: [] for _, k in cols}
        for pos, w in words:
            kind = cols[0][1]
            for start, k in cols:
                if pos >= start - 2:
                    kind = k
            cells[kind].append(w)
        if cells["name"] and (cells["name"][0].startswith("HCI_") or not rows):
            rows.append({})
        if not rows:
            continue
        for k, ws in cells.items():
            rows[-1].setdefault(k, []).extend(ws)
    result = []
    for r in rows:
        name, version = join_name(r.get("name", []))
        # A code can wrap inside its cell ("0x00B" above "8").
        codes = re.findall(r"0x[0-9A-Fa-f]{2,4}", "".join(r.get("code", [])))
        subs = re.findall(r"0x[0-9A-Fa-f]{2}", "".join(r.get("subevent", [])))
        result.append({
            "name": name,
            "version": version,
            "code": codes[0] if codes else None,
            "subevent": subs[0] if subs else None,
            "params": param_list(" ".join(r.get("params", []))),
            "return": param_list(" ".join(r.get("return", []))),
        })
    return result


def missing_params(body):
    """(parameter, value) rows of the "Missing parameters" table."""
    out = []
    in_table = False
    for line in body:
        if re.match(r"^Missing [Pp]arameters:?$", line):
            in_table = True
            continue
        if not in_table:
            continue
        if block_start(line):
            break
        if not line.strip() or re.match(r"^\s*Parameter\s+Value$", line):
            continue
        m = re.match(r"^ ([A-Za-z][A-Za-z0-9_\[\]]*)\s{2,}(\S.*)$", line)
        if m:
            out.append((m.group(1), re.sub(r"\s+", " ", m.group(2))))
        elif out:
            break
    return out


def param_blocks(body):
    """(block name, [(parameter, size)]) of the parameter blocks of a section."""
    blocks = []
    cur = None
    for line in body:
        b = block_start(line)
        if b:
            cur = (b, [])
            blocks.append(cur)
            continue
        if cur is None:
            continue
        if re.match(r"^(Event\(s\) generated|Description:|Missing [Pp]arameters)", line):
            cur = None
            continue
        m = PARAM.match(line)
        if m:
            # A parameter whose size depends on the version is listed once per version.
            cur[1].append((m.group(1) + (m.group(2) or ""), re.sub(r"\s+", " ", m.group(3))))
    return blocks


def subevents(body):
    """(code, version) from the value table of the Subevent_Code parameter."""
    rows = []
    in_table = False
    for line in body:
        if re.match(r"^Subevent_Code:\s+Size:", line):
            in_table = True
            continue
        if not in_table:
            continue
        if PARAM.match(line) or block_start(line):
            break
        m = re.match(r"^\s*(0x[0-9A-Fa-f]{2})\s+(\S.*)$", line)
        if m:
            rows.append([m.group(1), m.group(2)])
        elif rows and line.strip():
            rows[-1][1] += " " + line.strip()
    out = []
    for code, text in rows:
        m = re.match(r"(?i)^Subevent code for (?:the )?HCI_\S+(?:\s+\S+)*?\s*(\[v\d+\])?(?:\s*event)?"
                     r"\s*(\[v\d+\])?(?:\s*event)?\.?$", text)
        if m:
            out.append(("0x" + code[2:].upper(), m.group(1) or m.group(2)))
    return out


def subevent_code(row, version, subs):
    if row["subevent"]:
        return row["subevent"]
    match = [code for code, v in subs if (v or "") == version]
    if len(match) != 1 and len(subs) == 1:
        match = [subs[0][0]]
    return match[0] if len(match) == 1 else "?"


def main():
    for num, title, body in split_sections(part_e_lines(sys.argv[1])):
        rows = parse_table(body)
        is_command = title.endswith(" command")
        subs = subevents(body) if num.startswith("7.7.65.") else None
        pairs = []
        for r in rows:
            ver = f"[{r['version']}]" if r["version"] else ""
            code = r["code"] or "?"
            if subs is not None:
                code += "/" + subevent_code(r, ver, subs)
            pairs.append(f"{r['name']}{ver}={code}")
        print(f"## {num} {title}  [{' ; '.join(pairs)}]")
        if len(rows) > 1:
            print("  Versions:")
            for r in rows:
                ver = f"[{r['version']}]" if r["version"] else ""
                params = ", ".join(r["params"]) or "none"
                if is_command:
                    params += " -> " + (", ".join(r["return"]) or "none")
                print(f"    {r['name']}{ver}: {params}")
        missing = missing_params(body)
        if missing:
            print("  Missing parameters:")
            for n, v in missing:
                print(f"    {n}: {v}")
        for block, params in param_blocks(body):
            print(f"  {block}")
            for n, size in params:
                print(f"    {n}: {size}")


if __name__ == "__main__":
    main()
