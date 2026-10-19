// Bind ELF-relocated sBPF calls to public Solana syscall signatures.
// The eBPF processor otherwise treats each relocated call as a local function.
// @category Solana
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.UnsignedLongLongDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;
import java.io.BufferedReader;
import java.io.FileReader;

public class BindSolanaImports extends GhidraScript {
    private static final DataType U64 = UnsignedLongLongDataType.dataType;
    private static final DataType VOID = VoidDataType.dataType;
    private static final DataType BYTE = ByteDataType.dataType;
    private static final DataType BYTE_PTR = new PointerDataType(BYTE);
    private static final DataType INT_PTR = new PointerDataType(IntegerDataType.dataType);

    private record Signature(DataType result, String[] names, DataType[] types) {}

    private Signature signature(String name) {
        return switch (name) {
            case "sol_log_" -> new Signature(VOID,
                    new String[] {"message", "len"}, new DataType[] {BYTE_PTR, U64});
            case "sol_log_64_" -> new Signature(VOID,
                    new String[] {"a", "b", "c", "d", "e"},
                    new DataType[] {U64, U64, U64, U64, U64});
            case "sol_log_compute_units_" -> new Signature(VOID,
                    new String[] {}, new DataType[] {});
            case "sol_log_pubkey" -> new Signature(VOID,
                    new String[] {"pubkey"}, new DataType[] {BYTE_PTR});
            case "sol_create_program_address" -> new Signature(U64,
                    new String[] {"seeds", "seeds_len", "program_id", "result"},
                    new DataType[] {BYTE_PTR, U64, BYTE_PTR, BYTE_PTR});
            case "sol_try_find_program_address" -> new Signature(U64,
                    new String[] {"seeds", "seeds_len", "program_id", "result", "bump"},
                    new DataType[] {BYTE_PTR, U64, BYTE_PTR, BYTE_PTR, BYTE_PTR});
            case "sol_sha256", "sol_keccak256", "sol_blake3" -> new Signature(U64,
                    new String[] {"values", "values_len", "result"},
                    new DataType[] {BYTE_PTR, U64, BYTE_PTR});
            case "sol_secp256k1_recover" -> new Signature(U64,
                    new String[] {"hash", "recovery_id", "signature", "result"},
                    new DataType[] {BYTE_PTR, U64, BYTE_PTR, BYTE_PTR});
            case "sol_get_clock_sysvar", "sol_get_rent_sysvar", "sol_get_last_restart_slot",
                 "sol_get_epoch_schedule_sysvar", "sol_get_fees_sysvar",
                 "sol_get_epoch_rewards_sysvar" ->
                    new Signature(U64, new String[] {"addr"}, new DataType[] {BYTE_PTR});
            case "sol_memcpy_", "sol_memmove_" -> new Signature(VOID,
                    new String[] {"dst", "src", "n"}, new DataType[] {BYTE_PTR, BYTE_PTR, U64});
            case "sol_memset_" -> new Signature(VOID,
                    new String[] {"dst", "value", "n"}, new DataType[] {BYTE_PTR, BYTE, U64});
            case "sol_memcmp_" -> new Signature(VOID,
                    new String[] {"s1", "s2", "n", "result"},
                    new DataType[] {BYTE_PTR, BYTE_PTR, U64, INT_PTR});
            case "sol_set_return_data" -> new Signature(VOID,
                    new String[] {"data", "len"}, new DataType[] {BYTE_PTR, U64});
            case "sol_invoke_signed_c", "sol_invoke_signed_rust" -> new Signature(U64,
                    new String[] {"instruction", "accounts", "accounts_len", "seeds", "seeds_len"},
                    new DataType[] {BYTE_PTR, BYTE_PTR, U64, BYTE_PTR, U64});
            case "sol_get_return_data" -> new Signature(U64,
                    new String[] {"data", "length", "program_id"},
                    new DataType[] {BYTE_PTR, U64, BYTE_PTR});
            case "sol_log_data" -> new Signature(VOID,
                    new String[] {"slices", "count"}, new DataType[] {BYTE_PTR, U64});
            case "sol_get_processed_sibling_instruction" -> new Signature(U64,
                    new String[] {"index", "meta", "program_id", "data", "accounts"},
                    new DataType[] {U64, BYTE_PTR, BYTE_PTR, BYTE_PTR, BYTE_PTR});
            case "sol_get_stack_height", "sol_remaining_compute_units" ->
                    new Signature(U64, new String[] {}, new DataType[] {});
            case "sol_curve_validate_point" -> new Signature(U64,
                    new String[] {"curve", "point", "result"},
                    new DataType[] {U64, BYTE_PTR, BYTE_PTR});
            case "sol_curve_group_op" -> new Signature(U64,
                    new String[] {"curve", "operation", "left", "right", "result"},
                    new DataType[] {U64, U64, BYTE_PTR, BYTE_PTR, BYTE_PTR});
            case "sol_curve_multiscalar_mul" -> new Signature(U64,
                    new String[] {"curve", "scalars", "points", "count", "result"},
                    new DataType[] {U64, BYTE_PTR, BYTE_PTR, U64, BYTE_PTR});
            case "sol_curve_pairing_map" -> new Signature(U64,
                    new String[] {"curve", "point", "result"},
                    new DataType[] {U64, BYTE_PTR, BYTE_PTR});
            case "sol_alt_bn128_group_op", "sol_alt_bn128_compression" -> new Signature(U64,
                    new String[] {"operation", "input", "input_len", "result"},
                    new DataType[] {U64, BYTE_PTR, U64, BYTE_PTR});
            case "sol_big_mod_exp" -> new Signature(U64,
                    new String[] {"params", "result"}, new DataType[] {BYTE_PTR, BYTE_PTR});
            case "sol_poseidon" -> new Signature(U64,
                    new String[] {"parameters", "endianness", "values", "count", "result"},
                    new DataType[] {U64, U64, BYTE_PTR, U64, BYTE_PTR});
            case "sol_get_sysvar" -> new Signature(U64,
                    new String[] {"sysvar_id", "result", "offset", "length"},
                    new DataType[] {BYTE_PTR, BYTE_PTR, U64, U64});
            case "sol_get_epoch_stake" -> new Signature(U64,
                    new String[] {"vote_address"}, new DataType[] {BYTE_PTR});
            default -> null;
        };
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("usage: BindSolanaImports.java imports.tsv");
        }
        if (!currentProgram.getLanguageID().toString().startsWith("eBPF:")) {
            println("BindSolanaImports: 0 signatures (processor does not use eBPF call stubs)");
            return;
        }
        int bound = 0;
        int skipped = 0;
        try (BufferedReader input = new BufferedReader(new FileReader(args[0]))) {
            String line;
            while ((line = input.readLine()) != null) {
                if (line.isEmpty()) {
                    continue;
                }
                String[] fields = line.split("\t", 2);
                if (fields.length != 2) {
                    throw new IllegalArgumentException("invalid Solana import row: " + line);
                }
                Signature signature = signature(fields[1]);
                Address address = toAddr(Long.parseUnsignedLong(fields[0], 16));
                Function function = currentProgram.getFunctionManager().getFunctionAt(address);
                if (signature == null || function == null ||
                        !function.getName().startsWith("FUN_") ||
                        function.getSignatureSource() != SourceType.DEFAULT) {
                    skipped++;
                    continue;
                }
                try {
                    // Each callsite needs a unique Ghidra symbol. The exporter restores
                    // the shared public name in the C-like text afterward.
                    function.setName(fields[1] + "__reloc_" + fields[0], SourceType.ANALYSIS);
                    Parameter[] parameters = new Parameter[signature.types().length];
                    for (int i = 0; i < parameters.length; i++) {
                        parameters[i] = new ParameterImpl(signature.names()[i],
                                signature.types()[i], currentProgram);
                    }
                    function.replaceParameters(FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                            true, SourceType.ANALYSIS, parameters);
                    function.setReturnType(signature.result(), SourceType.ANALYSIS);
                    bound++;
                } catch (Exception exception) {
                    println("Import signature skipped at " + address + ": " + exception.getMessage());
                    skipped++;
                }
            }
        }
        println("BindSolanaImports: " + bound + " signatures, " + skipped + " skipped");
    }
}
