// Export high P-code evidence for later, program-independent value tracing.
// @category Solana
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighParam;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import java.io.File;
import java.io.FileWriter;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.Set;

public class ExportFlow extends GhidraScript {
    private static final int MAX_DEPTH = 5;

    private String quote(String value) {
        if (value == null) return "null";
        StringBuilder out = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\"' || c == '\\') out.append('\\');
            if (c == '\n') out.append("\\n");
            else if (c == '\r') out.append("\\r");
            else if (c == '\t') out.append("\\t");
            else if (c < 0x20) out.append(String.format("\\u%04x", (int)c));
            else out.append(c);
        }
        return out.append('\"').toString();
    }

    private String hex(long value) {
        return quote("0x" + Long.toHexString(value));
    }

    private String target(PcodeOp op) {
        if (op.getNumInputs() == 0 || op.getInput(0) == null) return "null";
        return hex(op.getInput(0).getOffset());
    }

    private String callee(PcodeOp op) {
        if (op.getNumInputs() == 0 || op.getInput(0) == null) return "null";
        Function function = currentProgram.getFunctionManager().getFunctionAt(op.getInput(0).getAddress());
        if (function == null) return "null";
        return quote(function.getName().replaceFirst("__reloc_[0-9a-f]+$", ""));
    }

    // A bounded backward slice. Unknowns are explicit, rather than guessed types.
    private String source(Varnode node, int depth, Set<Varnode> seen) {
        if (node == null) return "null";
        if (node.isConstant()) return "{\"kind\":\"constant\",\"value\":" + hex(node.getOffset()) + "}";
        HighVariable high = node.getHigh();
        if (high instanceof HighParam param) {
            return "{\"kind\":\"parameter\",\"index\":" + param.getSlot()
                + ",\"name\":" + quote(param.getName()) + "}";
        }
        if (depth == 0 || !seen.add(node)) {
            return "{\"kind\":\"unresolved\",\"varnode\":" + quote(node.toString()) + "}";
        }
        try {
            PcodeOp definition = node.getDef();
            if (definition == null) {
                return "{\"kind\":\"input\",\"varnode\":" + quote(node.toString()) + "}";
            }
            int opcode = definition.getOpcode();
            if (opcode == PcodeOp.CALL || opcode == PcodeOp.CALLIND) {
                return "{\"kind\":\"call_result\",\"target\":" + target(definition)
                    + ",\"callee\":" + callee(definition) + "}";
            }
            StringBuilder out = new StringBuilder("{\"kind\":\"operation\",\"op\":");
            out.append(quote(definition.getMnemonic())).append(",\"inputs\":[");
            for (int i = opcode == PcodeOp.LOAD ? 1 : opcode == PcodeOp.STORE ? 1 : 0;
                    i < definition.getNumInputs(); i++) {
                if (i > (opcode == PcodeOp.LOAD || opcode == PcodeOp.STORE ? 1 : 0)) out.append(',');
                out.append(source(definition.getInput(i), depth - 1, seen));
            }
            return out.append("]}").toString();
        } finally {
            seen.remove(node);
        }
    }

    private String source(Varnode node) {
        return source(node, MAX_DEPTH, Collections.newSetFromMap(new IdentityHashMap<>()));
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1 || args.length > 2) {
            throw new IllegalArgumentException("usage: ExportFlow.java output.json [function_address]");
        }
        Long selected = args.length == 2 ? Long.decode(args[1]) : null;
        File file = new File(args[0]);
        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException(decompiler.getLastMessage());
        int good = 0;
        int failed = 0;
        try (FileWriter writer = new FileWriter(file)) {
            writer.write("{\"schema\":1,\"language\":" + quote(currentProgram.getLanguageID().toString())
                + ",\"functions\":[");
            boolean firstFunction = true;
            for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
                if (selected != null && function.getEntryPoint().getOffset() != selected) continue;
                // Relocated syscall stubs are not program code. Their self-calls
                // duplicate actual callsites and obscure search results.
                if (function.getName().contains("__reloc_")) continue;
                DecompileResults result = decompiler.decompileFunction(function, 90, monitor);
                if (!firstFunction) writer.write(",");
                firstFunction = false;
                writer.write("{\"address\":" + hex(function.getEntryPoint().getOffset())
                    + ",\"name\":" + quote(function.getName()) + ",\"events\":[");
                if (result.decompileCompleted() && result.getHighFunction() != null) {
                    Iterator<PcodeOpAST> operations = result.getHighFunction().getPcodeOps();
                    boolean firstEvent = true;
                    while (operations.hasNext()) {
                        PcodeOpAST op = operations.next();
                        int opcode = op.getOpcode();
                        boolean arithmetic = opcode == PcodeOp.INT_SUB ||
                            opcode == PcodeOp.INT_MULT || opcode == PcodeOp.INT_DIV ||
                            opcode == PcodeOp.INT_SDIV ||
                            (opcode == PcodeOp.INT_ADD && op.getNumInputs() == 2 &&
                             !op.getInput(0).isConstant() && !op.getInput(1).isConstant());
                        if (opcode != PcodeOp.CALL && opcode != PcodeOp.CALLIND &&
                            opcode != PcodeOp.LOAD && opcode != PcodeOp.STORE &&
                            opcode != PcodeOp.RETURN && opcode != PcodeOp.CBRANCH &&
                            !arithmetic) continue;
                        if (!firstEvent) writer.write(",");
                        firstEvent = false;
                        writer.write("{\"address\":" + hex(op.getSeqnum().getTarget().getOffset())
                            + ",\"kind\":" + quote(arithmetic ? "arithmetic" :
                                opcode == PcodeOp.CBRANCH ? "branch" : op.getMnemonic().toLowerCase()));
                        if (arithmetic) writer.write(",\"op\":" + quote(op.getMnemonic()));
                        if (opcode == PcodeOp.CALL || opcode == PcodeOp.CALLIND) {
                            writer.write(",\"target\":" + target(op) + ",\"callee\":" + callee(op));
                        }
                        writer.write(",\"inputs\":[");
                        int start = (opcode == PcodeOp.CALL || opcode == PcodeOp.CALLIND ||
                            opcode == PcodeOp.LOAD || opcode == PcodeOp.STORE ||
                            opcode == PcodeOp.RETURN) ? 1 : 0;
                        for (int i = start; i < op.getNumInputs(); i++) {
                            if (i > start) writer.write(",");
                            writer.write(source(op.getInput(i)));
                        }
                        writer.write("]}");
                    }
                    good++;
                } else {
                    failed++;
                }
                writer.write("],\"status\":" + quote(result.decompileCompleted() &&
                    result.getHighFunction() != null ? "ok" : "failed") + "}");
            }
            writer.write("]}\n");
        } finally {
            decompiler.dispose();
        }
        println("ExportFlow: " + good + " functions, " + failed + " failed");
    }
}
