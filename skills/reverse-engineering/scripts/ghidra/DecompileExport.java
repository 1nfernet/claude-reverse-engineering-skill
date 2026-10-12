// Ghidra headless post-script: export decompiled C plus a program map to a text file.
//
// Why this exists: an agent working through a shell can't click around a GUI.
// This runs Ghidra's decompiler over every function (or a filtered subset) and
// writes plain C to one UTF-8 file you can grep and read in slices. It also
// writes a compact program map (entry points, imports with their libraries,
// defined strings) so you can orient before reading code.
//
// Java, not Python, on purpose: analyzeHeadless compiles and runs .java scripts
// out of the box, while Ghidra 12+ only runs .py scripts when launched through
// PyGhidra (Jython became an optional extension). See decompile_export.py for the
// PyGhidra variant.
//
//   analyzeHeadless <proj_dir> <proj_name> -import <target> \
//       -scriptPath <this_dir> -postScript DecompileExport.java <out_file> [name_filter] [max_funcs] \
//       -deleteProject
//
// Args: out_file (required); name_filter (optional, case-insensitive substring;
// pass "" to skip); max_funcs (optional, default 4000).
//
// analyzeHeadless exits 0 even when a post-script fails, so check that out_file
// exists and ends with the "exported N functions" footer.
//
// @category Analysis

import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.TreeSet;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public class DecompileExport extends GhidraScript {

    private static final String BAR = "========================================================================";

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("DecompileExport: missing output path argument; nothing written");
            return;
        }
        String outPath = args[0];
        String filter = (args.length > 1 && !args[1].isEmpty()) ? args[1].toLowerCase() : null;
        int maxFuncs = 4000;
        if (args.length > 2) {
            try {
                maxFuncs = Integer.parseInt(args[2]);
            }
            catch (NumberFormatException e) {
                printerr("DecompileExport: max_funcs '" + args[2] + "' is not a number; using 4000");
            }
        }

        Program program = currentProgram;
        try (PrintWriter out = new PrintWriter(
            new OutputStreamWriter(new FileOutputStream(outPath), StandardCharsets.UTF_8))) {

            out.println(BAR);
            out.println("GHIDRA DECOMPILE EXPORT");
            out.println("program  : " + program.getName());
            out.println("language : " + program.getLanguageID());
            out.println("compiler : " + program.getCompilerSpec().getCompilerSpecID());
            out.println("imagebase: " + program.getImageBase());
            if (filter != null) {
                out.println("filter   : name contains '" + args[1] + "'");
            }
            out.println(BAR);
            out.println();

            // entry points
            SymbolTable st = program.getSymbolTable();
            out.println("-- ENTRY POINTS --");
            AddressIterator eps = st.getExternalEntryPointIterator();
            int n = 0;
            while (eps.hasNext() && n < 200) {
                Address a = eps.next();
                Symbol s = st.getPrimarySymbol(a);
                out.println("  " + a + "  " + (s != null ? s.getName() : "?"));
                n++;
            }
            out.println();

            // imports, with the library each comes from
            FunctionManager fm = program.getFunctionManager();
            TreeSet<String> imports = new TreeSet<>();
            FunctionIterator ext = fm.getExternalFunctions();
            while (ext.hasNext()) {
                Function f = ext.next();
                ExternalLocation loc = f.getExternalLocation();
                String lib = (loc != null && loc.getLibraryName() != null) ? loc.getLibraryName() + "!" : "";
                imports.add(lib + f.getName());
            }
            out.println("-- IMPORTS (" + imports.size() + ") --");
            int shown = 0;
            for (String imp : imports) {
                if (shown++ >= 600) {
                    out.println("  ... (truncated)");
                    break;
                }
                out.println("  " + imp);
            }
            out.println();

            // defined strings: cheap, high-value context
            out.println("-- DEFINED STRINGS (first 400) --");
            DataIterator di = program.getListing().getDefinedData(true);
            int sc = 0;
            while (di.hasNext() && sc < 400) {
                Data d = di.next();
                if (!d.hasStringValue()) {
                    continue;
                }
                String v = d.getDefaultValueRepresentation();
                if (v == null || v.length() <= 4) {
                    continue;
                }
                if (v.length() > 120) {
                    v = v.substring(0, 120) + "...";
                }
                out.println("  " + d.getAddress() + "  " + v);
                sc++;
            }
            out.println();

            // decompiled functions
            out.println(BAR);
            out.println("DECOMPILED FUNCTIONS");
            out.println(BAR);
            DecompInterface ifc = new DecompInterface();
            ifc.openProgram(program);
            int done = 0;
            int thunks = 0;
            FunctionIterator it = fm.getFunctions(true);
            while (it.hasNext()) {
                if (monitor.isCancelled()) {
                    break;
                }
                Function f = it.next();
                if (filter != null && !f.getName().toLowerCase().contains(filter)) {
                    continue;
                }
                if (f.isThunk()) {
                    thunks++;
                    continue;
                }
                if (done >= maxFuncs) {
                    out.println();
                    out.println("/* reached max_funcs=" + maxFuncs + "; stopping */");
                    break;
                }
                out.println();
                out.println("/* ---- " + f.getName() + " @ " + f.getEntryPoint() + " ---- */");
                DecompileResults res = ifc.decompileFunction(f, 60, monitor);
                if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                    out.print(res.getDecompiledFunction().getC());
                }
                else {
                    out.println("/* decompilation failed: " +
                        (res != null ? res.getErrorMessage() : "no result") + " */");
                }
                done++;
            }
            ifc.dispose();
            out.println();
            out.println("/* exported " + done + " functions (" + thunks + " thunks skipped) */");
        }
        println("DecompileExport: wrote " + outPath);
    }
}
