# Ghidra headless post-script: decompile functions to C-like pseudocode (FR-RE-2).
#
# Runs inside Ghidra (Jython) via:
#   analyzeHeadless <proj> <name> -import <bin> \
#       -scriptPath <dir> -postScript ifda_decompile.py <out.json> [name1,name2,...]
#
# Args: [0] output JSON path; [1] optional comma-separated function-name filter
# (empty => all functions). Emits {"program", "functions":[{name,address,
# pseudocode,signature}]}. This file is intentionally dependency-free Jython.
#@category ifda

import json

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


def _run():
    args = getScriptArgs()
    if not args:
        print("ifda_decompile: missing output path argument")
        return
    out_path = args[0]
    name_filter = None
    if len(args) > 1 and args[1].strip():
        name_filter = set(n for n in args[1].split(",") if n)

    decomp = DecompInterface()
    decomp.openProgram(currentProgram)
    monitor = ConsoleTaskMonitor()

    fm = currentProgram.getFunctionManager()
    results = []
    for func in fm.getFunctions(True):  # True = forward order
        if func.isExternal() or func.isThunk():
            continue
        name = func.getName()
        if name_filter is not None and name not in name_filter:
            continue
        code = ""
        try:
            res = decomp.decompileFunction(func, 60, monitor)
            if res is not None and res.decompileCompleted():
                code = res.getDecompiledFunction().getC()
        except Exception as e:  # never let one function abort the batch
            code = "/* decompilation error: %s */" % e
        results.append({
            "name": name,
            "address": "0x%x" % func.getEntryPoint().getOffset(),
            "signature": func.getSignature().getPrototypeString(),
            "pseudocode": code,
        })

    decomp.dispose()
    f = open(out_path, "w")
    try:
        json.dump({"program": currentProgram.getName(), "functions": results}, f)
    finally:
        f.close()
    print("ifda_decompile: wrote %d functions to %s" % (len(results), out_path))


_run()
