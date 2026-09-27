package org.briarproject.bramble.rendezvous;

import org.briarproject.bramble.api.crypto.CryptoComponent;
import org.briarproject.bramble.api.crypto.SecretKey;
import org.briarproject.bramble.api.plugin.TransportId;
import org.briarproject.bramble.api.rendezvous.KeyMaterialSource;

import java.util.Map;

/**
 * Reference bytes for the rendezvous key schedule. Lives in this package
 * because RendezvousCryptoImpl and KeyMaterialSourceImpl are package-private.
 */
public class Vectors6 {

	private static final String LAN = "org.briarproject.bramble.lan";

	public static void dump(Map<String, String> out) throws Exception {
		CryptoComponent crypto =
				org.briarproject.bramble.crypto.Vectors.newCrypto();
		RendezvousCryptoImpl rc = new RendezvousCryptoImpl(crypto);

		// A fixed master key, so the values are reproducible.
		byte[] master = new byte[32];
		for (int i = 0; i < 32; i++) master[i] = (byte) i;
		SecretKey masterKey = new SecretKey(master);

		SecretKey rk = rc.deriveRendezvousKey(masterKey);
		out.put("rv_key", hex(rk.getBytes()));

		KeyMaterialSource src =
				rc.createKeyMaterialSource(rk, new TransportId(LAN));
		// Briar takes Alice's seed first, then Bob's -- each 32 bytes.
		out.put("rv_alice_seed", hex(src.getKeyMaterial(32)));
		out.put("rv_bob_seed", hex(src.getKeyMaterial(32)));

		// And the Tor transport, whose identifier differs.
		KeyMaterialSource tor = rc.createKeyMaterialSource(rk,
				new TransportId("org.briarproject.bramble.tor"));
		out.put("rv_tor_alice_seed", hex(tor.getKeyMaterial(32)));
		out.put("rv_tor_bob_seed", hex(tor.getKeyMaterial(32)));
	}

	private static String hex(byte[] b) {
		StringBuilder s = new StringBuilder();
		for (byte x : b) s.append(String.format("%02x", x));
		return s.toString();
	}
}
