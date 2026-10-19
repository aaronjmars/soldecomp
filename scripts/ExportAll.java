// Export every function from a headless Ghidra analysis as C-like source.
// @category Solana
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import java.io.File;
import java.io.FileWriter;

public class ExportAll extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("usage: ExportAll.java output_directory");
        }
        File directory = new File(args[0]);
        if (!directory.isDirectory() && !directory.mkdirs()) {
            throw new IllegalArgumentException("cannot create " + directory);
        }
        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        if (!decompiler.openProgram(currentProgram)) {
            throw new IllegalStateException(decompiler.getLastMessage());
        }
        int good = 0;
        int failed = 0;
        try (FileWriter index = new FileWriter(new File(directory, "index.tsv"))) {
            index.write("address\tname\tstatus\n");
            for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
                String address = String.format("%016x", function.getEntryPoint().getOffset());
                DecompileResults result = decompiler.decompileFunction(function, 90, monitor);
                if (!result.decompileCompleted() || result.getDecompiledFunction() == null) {
                    index.write(address + "\t" + function.getName() + "\tfailed\n");
                    failed++;
                    continue;
                }
                try (FileWriter output = new FileWriter(new File(directory, address + ".c"))) {
                    output.write("/* " + function.getName() + " at 0x" + address + " */\n");
                    output.write(result.getDecompiledFunction().getC());
                }
                index.write(address + "\t" + function.getName() + "\tok\n");
                good++;
            }
        } finally {
            decompiler.dispose();
        }
        println("ExportAll: " + good + " decompiled, " + failed + " failed");
    }
}
