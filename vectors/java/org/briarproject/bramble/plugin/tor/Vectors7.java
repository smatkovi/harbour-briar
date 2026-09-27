package org.briarproject.bramble.plugin.tor;

import org.briarproject.bramble.api.crypto.CryptoComponent;

import java.util.Map;

/**
 * Reference values for turning a rendezvous seed into a v3 onion address and
 * the private key blob Tor's ADD_ONION wants. TorRendezvousCryptoImpl is
 * package-private, hence this package.
 */
public class Vectors7 {

	public static void dump(Map<String, String> out) throws Exception {
		CryptoComponent crypto =
				org.briarproject.bramble.crypto.Vectors.newCrypto();
		TorRendezvousCryptoImpl trc = new TorRendezvousCryptoImpl(crypto);

		byte[] seed = new byte[32];
		for (int i = 0; i < 32; i++) seed[i] = (byte) (0x40 + i);

		out.put("rv_onion", trc.getOnion(seed));
		out.put("rv_blob", trc.getPrivateKeyBlob(seed));
	}
}
