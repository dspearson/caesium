package caesium.impl;

import jnr.ffi.Struct;
import jnr.ffi.Runtime;

public class SecretStreamState extends Struct {
    public SecretStreamState(jnr.ffi.Runtime runtime) {
        super(runtime);
    }

    public final char[] k = new char[32];
    public final char[] nonce = new char[12];
    public final char[] _pad = new char[8];

    public static SecretStreamState of(jnr.ffi.Pointer pointer) {
        SecretStreamState sss = new SecretStreamState(jnr.ffi.Runtime.getSystemRuntime());
        sss.useMemory(pointer);
        return sss;
    }
}
