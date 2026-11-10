#!/usr/bin/env python3
"""Patch NetAnim's source so it auto-loads a trace given on the command line.

Upstream NetAnim ignores ``argv`` entirely: it always opens with an empty
canvas and asks the user to pick an XML trace by hand. NetShield launches it
with a trace path (``netanim run.xml``) and needs that trace to load and play
on its own. This script applies three small, idempotent edits to the NetAnim
source tree so the binary honours ``argv[1]``:

  * ``animatormode.h``   - declare a public ``openTraceFileFromCommandLine``.
  * ``animatormode.cpp`` - implement it, mirroring the proven file-open slot
    (``systemReset`` -> set the trace name -> ``parseXMLTraceFile``).
  * ``main.cpp``         - when a path is given, load it once the Qt event
    loop is running (via a zero-delay ``QTimer``).

Usage::

    python3 patch_netanim.py /path/to/netanim/src

Running it again is a no-op. It fails loudly if an expected anchor is missing
(e.g. a NetAnim version whose source has moved on), so the build surfaces the
problem instead of silently producing a binary that ignores ``argv``.
"""

from __future__ import annotations

import sys
from pathlib import Path

HEADER_ANCHOR = "  static AnimatorMode * getInstance ();\n"
HEADER_ADD = HEADER_ANCHOR + "  void openTraceFileFromCommandLine (QString traceFileName);\n"

CPP_ANCHOR = "  return pAnimatorMode;\n}\n"
CPP_ADD = CPP_ANCHOR + (
    "\n"
    "void\n"
    "AnimatorMode::openTraceFileFromCommandLine (QString traceFileName)\n"
    "{\n"
    "  if (traceFileName == \"\")\n"
    "    return;\n"
    "  StatsMode::getInstance ()->systemReset ();\n"
    "  systemReset ();\n"
    "  m_traceFileName = traceFileName;\n"
    "  if (parseXMLTraceFile (traceFileName))\n"
    "    m_fileOpenButton->setEnabled (true);\n"
    "  StatsMode::getInstance ()->systemReset ();\n"
    "  QApplication::processEvents ();\n"
    "}\n"
)

MAIN_INCLUDE_ANCHOR = '#include "netanim.h"\n'
MAIN_INCLUDE_ADD = MAIN_INCLUDE_ANCHOR + '#include "animatormode.h"\n#include <QTimer>\n'

MAIN_EXEC_ANCHOR = "  netanim::NetAnim netAnim;\n  return app.exec ();\n"
MAIN_EXEC_ADD = (
    "  netanim::NetAnim netAnim;\n"
    "  if (argc > 1)\n"
    "    {\n"
    "      QString traceFile = QString::fromLocal8Bit (argv[1]);\n"
    "      QTimer::singleShot (0, [traceFile] () {\n"
    "          netanim::AnimatorMode::getInstance ()->openTraceFileFromCommandLine (traceFile);\n"
    "        });\n"
    "    }\n"
    "  return app.exec ();\n"
)


def _patch(path: Path, anchor: str, replacement: str, sentinel: str) -> bool:
    """Replace *anchor* with *replacement* in *path* unless already applied."""
    text = path.read_text(encoding="utf-8")
    if sentinel in text:
        return False
    if anchor not in text:
        raise SystemExit(f"anchor not found in {path.name}: {anchor!r}")
    path.write_text(text.replace(anchor, replacement, 1), encoding="utf-8")
    return True


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        raise SystemExit("usage: patch_netanim.py <netanim-src-dir>")
    src = Path(argv[1])
    if not (src / "main.cpp").exists():
        raise SystemExit(f"not a NetAnim src dir (no main.cpp): {src}")

    changed = False
    changed |= _patch(src / "animatormode.h", HEADER_ANCHOR, HEADER_ADD,
                       "openTraceFileFromCommandLine")
    changed |= _patch(src / "animatormode.cpp", CPP_ANCHOR, CPP_ADD,
                       "openTraceFileFromCommandLine")
    changed |= _patch(src / "main.cpp", MAIN_INCLUDE_ANCHOR, MAIN_INCLUDE_ADD,
                      '#include "animatormode.h"')
    changed |= _patch(src / "main.cpp", MAIN_EXEC_ANCHOR, MAIN_EXEC_ADD,
                      "openTraceFileFromCommandLine")

    print("NetAnim auto-load patch applied" if changed
          else "NetAnim auto-load patch already present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
