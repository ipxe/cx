package org.ipxe.cx;

class CxJni {

	static {
		System.loadLibrary("cxjni");
	}

	private static native int genSeedLen(int type);
	private static native int genMaxIterations(int type);
	private static native long genInstantiate(int type, byte[] seed);
	private static native byte[] genIterate(long handle);
	private static native void genUninstantiate(long handle);

	public static void main(String[] args) {}
}
