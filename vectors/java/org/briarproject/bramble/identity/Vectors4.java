package org.briarproject.bramble.identity;

import org.briarproject.bramble.api.crypto.SignaturePublicKey;
import org.briarproject.bramble.api.identity.Author;

import java.util.Map;

import static org.briarproject.bramble.crypto.Vectors.hex;
import static org.briarproject.bramble.crypto.Vectors.newCrypto;

/** Author identifiers, from the real factory. */
public class Vectors4 {

	public static void dump(Map<String, String> out) throws Exception {
		AuthorFactoryImpl af = new AuthorFactoryImpl(newCrypto());
		byte[] pub = new byte[32];
		for (int i = 0; i < 32; i++) pub[i] = (byte) (0x20 + i);
		Author a = af.createAuthor("Sebastian", new SignaturePublicKey(pub));
		out.put("author_pub", hex(pub));
		out.put("author_id", hex(a.getId().getBytes()));
	}
}
