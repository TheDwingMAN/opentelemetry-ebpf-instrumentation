#!/usr/bin/env python3
"""Stage, with git add -p, the hunks of a file that contain any of the given markers.
Usage: stage_hunks.py <file> <marker>...   (marker "ALL" stages every hunk)"""
import re
import subprocess
import sys

path, markers = sys.argv[1], sys.argv[2:]
diff = subprocess.run(["git", "diff", "--", path], capture_output=True, text=True, check=True).stdout
hunks = re.split(r"(?m)^(?=@@)", diff)[1:]
answers = ["y" if "ALL" in markers or any(m in h for m in markers) else "n" for h in hunks]
print(path, "".join(answers))
subprocess.run(["git", "add", "-p", "--", path], input="\n".join(answers) + "\n", text=True,
               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
