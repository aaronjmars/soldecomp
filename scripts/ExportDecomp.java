// Export one function from a headless Ghidra analysis into a text file.
// @category Solana
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import java.io.FileWriter;

public class ExportDecomp extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) {
            throw new IllegalArgumentException("usage: ExportDecomp.java output.txt function_address_hex");
        }
        long wanted = Long.decode(args[1]);
        Function found = null;
        for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
            if (function.getEntryPoint().getOffset() == wanted) {
                found = function;
                break;
            }
        }
        try (FileWriter writer = new FileWriter(args[0])) {
            writer.write("program=" + currentProgram.getName() + "\n");
            writer.write("language=" + currentProgram.getLanguageID() + "\n");
            writer.write("functions=" + currentProgram.getFunctionManager().getFunctionCount() + "\n");
            if (found == null) {
                writer.write("error=function not found at " + args[1] + "\n");
                return;
            }
            writer.write("function=" + found.getName() + "\n");
            DecompInterface decompiler = new DecompInterface();
            try {
                decompiler.toggleCCode(true);
                if (!decompiler.openProgram(currentProgram)) {
                    writer.write("error=" + decompiler.getLastMessage() + "\n");
                    return;
                }
                DecompileResults result = decompiler.decompileFunction(found, 90, monitor);
                if (!result.decompileCompleted() || result.getDecompiledFunction() == null) {
                    writer.write("error=" + result.getErrorMessage() + "\n");
                    return;
                }
                writer.write(result.getDecompiledFunction().getC());
            } finally {
                decompiler.dispose();
            }
        }
    }
}
