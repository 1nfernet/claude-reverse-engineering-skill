# Ghidra headless post-script: export decompiled C + a program map to a text file.
#
# Why this exists: an agent working through a shell can't click around a GUI.
# This runs Ghidra's decompiler over every function (or a filtered subset) and
# writes plain C to one file you can read in slices with sed/grep. It also writes
# a compact program map (entry points, imports, exports, strings) so you can
# orient before reading code.
#
# This is the PyGhidra variant of DecompileExport.java. Ghidra 12+ runs .py
# scripts only when launched through PyGhidra (Jython is an optional extension),
# so prefer DecompileExport.java with plain analyzeHeadless. Syntax stays
# Jython-2.7-compatible for older Ghidra installs that still use Jython.
#
# Run it under PyGhidra (see references/tools.md for a non-interactive setup):
#
#   pyghidraRun -H <proj_dir> <proj_name> -import <target> \
#       -scriptPath <this_dir> -postScript decompile_export.py <out_file> [name_filter] [max_funcs]
#
# Args (from getScriptArgs()):
#   out_file    required  where to write the export
#   name_filter optional  only functions whose name contains this (case-insensitive)
#   max_funcs   optional  stop after this many functions (default 4000; keeps output sane)
#
# @category Analysis

import codecs

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


def _getarg(args, i, default):
    return args[i] if len(args) > i and args[i] != "" else default


def main():
    args = getScriptArgs()  # noqa: F821  (injected by Ghidra)
    if len(args) < 1:
        print("decompile_export: missing output path argument; nothing written")
        return

    out_path = args[0]
    name_filter = _getarg(args, 1, None)
    try:
        max_funcs = int(_getarg(args, 2, "4000"))
    except ValueError:
        max_funcs = 4000

    program = currentProgram  # noqa: F821
    name_lc = name_filter.lower() if name_filter else None

    # codecs.open, not open(): under Jython 2.7 a plain text file encodes as ASCII,
    # so the first non-ASCII string or decompiled literal would raise and abort the
    # export. codecs.open writes UTF-8 in both Jython and CPython 3.
    fh = codecs.open(out_path, "w", "utf-8", "replace")
    try:
        # ---- header / program map -------------------------------------------
        fh.write("=" * 72 + "\n")
        fh.write("GHIDRA DECOMPILE EXPORT\n")
        fh.write("program : %s\n" % program.getName())
        fh.write("language: %s\n" % program.getLanguageID())
        fh.write("compiler: %s\n" % program.getCompilerSpec().getCompilerSpecID())
        img = program.getImageBase()
        fh.write("imagebase: %s\n" % (img.toString() if img is not None else "?"))
        if name_filter:
            fh.write("filter  : name contains '%s'\n" % name_filter)
        fh.write("=" * 72 + "\n\n")

        # entry points
        st = program.getSymbolTable()
        fh.write("-- ENTRY POINTS --\n")
        count = 0
        for addr in st.getExternalEntryPointIterator():
            sym = st.getPrimarySymbol(addr)
            label = sym.getName() if sym is not None else "?"
            fh.write("  %s  %s\n" % (addr.toString(), label))
            count += 1
            if count >= 200:
                fh.write("  ... (truncated)\n")
                break
        fh.write("\n")

        # imports (external functions)
        fh.write("-- IMPORTS (external functions) --\n")
        fm = program.getFunctionManager()
        ext_names = []
        ext_iter = fm.getExternalFunctions()
        while ext_iter.hasNext():
            ext_names.append(ext_iter.next().getName())
        for n in sorted(set(ext_names))[:400]:
            fh.write("  %s\n" % n)
        fh.write("\n")

        # defined strings (data) -- cheap, high-value context
        fh.write("-- DEFINED STRINGS (sample) --\n")
        listing = program.getListing()
        data_iter = listing.getDefinedData(True)
        s_count = 0
        while data_iter.hasNext() and s_count < 400:
            d = data_iter.next()
            dt = d.getDataType().getName().lower()
            if "unicode" in dt or "string" in dt:
                val = d.getDefaultValueRepresentation()
                if val and len(val) > 4:
                    if len(val) > 120:
                        val = val[:120] + "..."
                    fh.write("  %s  %s\n" % (d.getAddress().toString(), val))
                    s_count += 1
        fh.write("\n")

        # ---- decompiled functions -------------------------------------------
        decomp = DecompInterface()
        decomp.openProgram(program)
        monitor = ConsoleTaskMonitor()

        fh.write("=" * 72 + "\n")
        fh.write("DECOMPILED FUNCTIONS\n")
        fh.write("=" * 72 + "\n")

        func_iter = fm.getFunctions(True)  # True = forward address order
        done = 0
        skipped = 0
        for func in func_iter:
            if done >= max_funcs:
                fh.write("\n/* reached max_funcs=%d; stopping */\n" % max_funcs)
                break
            fname = func.getName()
            if name_lc is not None and name_lc not in fname.lower():
                continue
            if func.isThunk():
                skipped += 1
                continue
            entry = func.getEntryPoint().toString()
            fh.write("\n/* ---- %s @ %s ---- */\n" % (fname, entry))
            try:
                res = decomp.decompileFunction(func, 60, monitor)
                if res is not None and res.decompileCompleted():
                    fh.write(res.getDecompiledFunction().getC())
                else:
                    msg = res.getErrorMessage() if res is not None else "no result"
                    fh.write("/* decompilation failed: %s */\n" % msg)
            except Exception as e:
                fh.write("/* exception: %s */\n" % str(e))
            done += 1

        fh.write("\n/* exported %d functions (%d thunks skipped) */\n" % (done, skipped))
        decomp.dispose()
    finally:
        fh.close()

    print("decompile_export: wrote %s" % out_path)


# Portability: only syntax valid in both Jython 2.7 and CPython 3 -- print() with
# one argument, `except ... as e`, %-formatting -- so the file runs on old
# Jython-based Ghidra and on PyGhidra (verified on Ghidra 12.1.4 / pyghidra 3.1).

main()
