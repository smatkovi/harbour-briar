package org.briarproject.bramble.contact;

import org.briarproject.bramble.api.crypto.AgreementPrivateKey;
import org.briarproject.bramble.api.crypto.AgreementPublicKey;
import org.briarproject.bramble.api.crypto.CryptoComponent;
import org.briarproject.bramble.api.crypto.KeyPair;
import org.briarproject.bramble.api.crypto.PublicKey;
import org.briarproject.bramble.api.crypto.SecretKey;
import org.briarproject.bramble.api.crypto.SignaturePrivateKey;

import java.util.Map;

import static org.briarproject.bramble.crypto.Vectors.hex;
import static org.briarproject.bramble.crypto.Vectors.newCrypto;

/** Handshake, contact exchange and link reference values. */
public class Vectors5 {

	/** Clock has more than one method, so no lambda. */
	private static class FixedClock
			implements org.briarproject.bramble.api.system.Clock {

		@Override
		public long currentTimeMillis() {
			return 1700000000000L;
		}

		@Override
		public void sleep(long ms) {
		}
	}

	public static void dump(Map<String, String> out) throws Exception {
		CryptoComponent crypto = newCrypto();
		HandshakeCryptoImpl hc = new HandshakeCryptoImpl(crypto);
		ContactExchangeCryptoImpl ec = new ContactExchangeCryptoImpl(crypto);

		// Four fixed agreement key pairs: both peers, static and ephemeral
		byte[][] privs = new byte[4][32];
		for (int k = 0; k < 4; k++) {
			for (int i = 0; i < 32; i++) privs[k][i] = (byte) (0x11 * (k + 1) + i);
			privs[k][0] &= 248;
			privs[k][31] &= 127;
			privs[k][31] |= 64;
		}
		KeyPair[] kps = new KeyPair[4];
		for (int k = 0; k < 4; k++) {
			byte[] pub = org.briarproject.bramble.crypto.Vectors.pub(privs[k]);
			kps[k] = new KeyPair(new AgreementPublicKey(pub),
					new AgreementPrivateKey(privs[k]));
			out.put("hs_priv_" + k, hex(privs[k]));
			out.put("hs_pub_" + k, hex(pub));
		}
		// 0 = our static, 1 = their static, 2 = our ephemeral, 3 = their ephemeral
		SecretKey masterAlice = hc.deriveMasterKey_0_1(kps[1].getPublic(),
				kps[3].getPublic(), kps[0], kps[2], true);
		SecretKey masterBob = hc.deriveMasterKey_0_1(kps[1].getPublic(),
				kps[3].getPublic(), kps[0], kps[2], false);
		out.put("hs_master_alice", hex(masterAlice.getBytes()));
		out.put("hs_master_bob", hex(masterBob.getBytes()));
		out.put("hs_proof_alice", hex(hc.proveOwnership(masterAlice, true)));
		out.put("hs_proof_bob", hex(hc.proveOwnership(masterAlice, false)));

		out.put("ex_header_alice", hex(ec.deriveHeaderKey(masterAlice, true).getBytes()));
		out.put("ex_header_bob", hex(ec.deriveHeaderKey(masterAlice, false).getBytes()));
		byte[] seed = new byte[32];
		for (int i = 0; i < 32; i++) seed[i] = (byte) (0x40 + i);
		out.put("ex_sig_alice", hex(ec.sign(new SignaturePrivateKey(seed),
				masterAlice, true)));

		// Handshake link
		PendingContactFactoryImpl pf =
				new PendingContactFactoryImpl(crypto, new FixedClock());
		PublicKey linkKey = kps[0].getPublic();
		out.put("link", pf.createHandshakeLink(linkKey));
		out.put("link_pending_id",
				hex(pf.createPendingContact(pf.createHandshakeLink(linkKey), "x")
						.getId().getBytes()));
	}
}
