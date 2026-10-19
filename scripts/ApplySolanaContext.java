// Apply facts recovered from an sBPF ELF before exporting C-like output.
// @category Solana
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.UnsignedLongLongDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import java.io.BufferedReader;
import java.io.FileReader;

public class ApplySolanaContext extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("usage: ApplySolanaContext.java hints.tsv");
        }
        int returns = 0;
        int labels = 0;
        boolean inferReturns = currentProgram.getLanguageID().toString().startsWith("eBPF:");
        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        if (!decompiler.openProgram(currentProgram)) {
            throw new IllegalStateException(decompiler.getLastMessage());
        }
        try (BufferedReader input = new BufferedReader(new FileReader(args[0]))) {
            String line;
            while ((line = input.readLine()) != null) {
                if (line.isEmpty()) {
                    continue;
                }
                String[] fields = line.split("\t", 3);
                if (fields.length != 3) {
                    throw new IllegalArgumentException("invalid Solana context row: " + line);
                }
                Address address = toAddr(Long.parseUnsignedLong(fields[1], 16));
                if (fields[0].equals("return")) {
                    Function function = currentProgram.getFunctionManager().getFunctionAt(address);
                    if (inferReturns && function != null && function.getSignatureSource() == SourceType.DEFAULT &&
                            function.getReturnType().getName().equals("undefined")) {
                        DecompileResults result = decompiler.decompileFunction(function, 90, monitor);
                        if (result.decompileCompleted() && result.getHighFunction() != null &&
                                result.getHighFunction().getFunctionPrototype().getNumParams() > 0 &&
                                result.getHighFunction().getFunctionPrototype().getReturnType()
                                        .isEquivalent(VoidDataType.dataType)) {
                            try {
                                HighFunctionDBUtil.commitParamsToDatabase(result.getHighFunction(), true,
                                        ReturnCommitOption.NO_COMMIT, SourceType.ANALYSIS);
                                function.setReturnType(UnsignedLongLongDataType.dataType, SourceType.ANALYSIS);
                                returns++;
                            } catch (Exception exception) {
                                println("Return hint skipped at " + address + ": " + exception.getMessage());
                            }
                        }
                    }
                } else if (fields[0].equals("pubkey")) {
                    createLabel(address, fields[2], true);
                    labels++;
                } else {
                    throw new IllegalArgumentException("unknown Solana context row: " + line);
                }
            }
        } finally {
            decompiler.dispose();
        }
        println("ApplySolanaContext: " + returns + " return signatures, " + labels + " program ID labels");
    }
}
