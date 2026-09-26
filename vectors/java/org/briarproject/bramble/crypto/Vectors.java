package org.briarproject.bramble.crypto;

import org.briarproject.bramble.api.crypto.AgreementPrivateKey;
import org.briarproject.bramble.api.crypto.AgreementPublicKey;
import org.briarproject.bramble.api.crypto.CryptoComponent;
import org.briarproject.bramble.api.crypto.KeyPair;
import org.briarproject.bramble.api.crypto.PrivateKey;
import org.briarproject.bramble.api.crypto.PublicKey;
import org.briarproject.bramble.api.crypto.SecretKey;
import org.briarproject.bramble.api.crypto.SignaturePrivateKey;
import org.briarproject.bramble.api.crypto.SignaturePublicKey;
import org.briarproject.bramble.api.plugin.TransportId;
import org.briarproject.bramble.api.transport.IncomingKeys;
import org.briarproject.bramble.api.transport.OutgoingKeys;
import org.briarproject.bramble.api.transport.TransportKeys;

import java.io.ByteArrayOutputStream;
import java.util.Map;

/**
 * Dumps reference bytes from the real bramble-core classes, so the Rust
 * reimplementation can be diffed against them layer by layer.
 *
 * Lives in the crypto package because the classes it instantiates are
 * package-private.
 */
public class Vectors {

	public static CryptoComponent newCrypto() {
		return new CryptoComponentImpl(() -> null, null);
	}

	// Fixed inputs, so every run prints the same bytes
	static final byte[] A = "briar-vector-input-a".getBytes();
	static final byte[] B = new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
	static final byte[] KEY = new byte[32];
	static final byte[] SEED = new byte[32];
	static final byte[] AGREE_PRIV_1 = new byte[32];
	static final byte[] AGREE_PRIV_2 = new byte[32];

	static {
		for (int i = 0; i < 32; i++) {
			KEY[i] = (byte) (i + 1);
			SEED[i] = (byte) (0x40 + i);
			// Clamped the way curve25519 clamps private keys
			AGREE_PRIV_1[i] = (byte) (0x80 + i);
			AGREE_PRIV_2[i] = (byte) (0xc0 - i);
		}
		clamp(AGREE_PRIV_1);
		clamp(AGREE_PRIV_2);
	}

	private static void clamp(byte[] k) {
		k[0] &= 248;
		k[31] &= 127;
		k[31] |= 64;
	}

	public static void dump(Map<String, String> out) throws Exception {
		CryptoComponent crypto = newCrypto();
		SecretKey key = new SecretKey(KEY);

		out.put("hash", hex(crypto.hash("test/LABEL", A, B)));
		out.put("hash_empty", hex(crypto.hash("")));
		out.put("mac", hex(crypto.mac("test/LABEL", key, A, B)));
		out.put("derive_key", hex(crypto.deriveKey("test/LABEL", key, A).getBytes()));

		// Ed25519: private key is the seed, public key is the compressed point
		PrivateKey sigPriv = new SignaturePrivateKey(SEED);
		out.put("sign_seed", hex(SEED));
		out.put("sign", hex(crypto.sign("test/SIGN", A, sigPriv)));

		// Curve25519 agreement
		KeyPair kp1 = new KeyPair(new AgreementPublicKey(pub(AGREE_PRIV_1)),
				new AgreementPrivateKey(AGREE_PRIV_1));
		KeyPair kp2 = new KeyPair(new AgreementPublicKey(pub(AGREE_PRIV_2)),
				new AgreementPrivateKey(AGREE_PRIV_2));
		out.put("agree_priv_1", hex(AGREE_PRIV_1));
		out.put("agree_priv_2", hex(AGREE_PRIV_2));
		out.put("agree_pub_1", hex(kp1.getPublic().getEncoded()));
		out.put("agree_pub_2", hex(kp2.getPublic().getEncoded()));
		CryptoComponentImpl impl = (CryptoComponentImpl) crypto;
		out.put("agree_raw", hex(impl.performRawKeyAgreement(kp1.getPrivate(),
				kp2.getPublic())));
		out.put("derive_shared", hex(crypto.deriveSharedSecret("test/SHARED",
				kp2.getPublic(), kp1, A).getBytes()));

		// Transport crypto
		TransportCryptoImpl tc = new TransportCryptoImpl(crypto);
		TransportId lan = new TransportId("org.briarproject.bramble.lan");
		SecretKey staticMaster =
				tc.deriveStaticMasterKey(kp2.getPublic(), kp1);
		out.put("static_master_key", hex(staticMaster.getBytes()));
		out.put("is_alice_1", String.valueOf(tc.isAlice(kp2.getPublic(), kp1)));
		SecretKey rootPending = tc.deriveHandshakeRootKey(staticMaster, true);
		SecretKey rootContact = tc.deriveHandshakeRootKey(staticMaster, false);
		out.put("pending_root_key", hex(rootPending.getBytes()));
		out.put("contact_root_key", hex(rootContact.getBytes()));

		TransportKeys hs = tc.deriveHandshakeKeys(lan, rootPending, 7, true);
		out.put("hs_out_tag", hex(hs.getCurrentOutgoingKeys().getTagKey().getBytes()));
		out.put("hs_out_header", hex(hs.getCurrentOutgoingKeys().getHeaderKey().getBytes()));
		out.put("hs_in_curr_tag", hex(hs.getCurrentIncomingKeys().getTagKey().getBytes()));
		out.put("hs_in_curr_header", hex(hs.getCurrentIncomingKeys().getHeaderKey().getBytes()));
		out.put("hs_in_prev_tag", hex(hs.getPreviousIncomingKeys().getTagKey().getBytes()));
		out.put("hs_in_next_tag", hex(hs.getNextIncomingKeys().getTagKey().getBytes()));

		TransportKeys rot = tc.deriveRotationKeys(lan, rootContact, 7, true, true);
		out.put("rot_out_tag", hex(rot.getCurrentOutgoingKeys().getTagKey().getBytes()));
		out.put("rot_out_header", hex(rot.getCurrentOutgoingKeys().getHeaderKey().getBytes()));
		out.put("rot_in_curr_tag", hex(rot.getCurrentIncomingKeys().getTagKey().getBytes()));
		out.put("rot_in_curr_header", hex(rot.getCurrentIncomingKeys().getHeaderKey().getBytes()));
		out.put("rot_in_prev_tag", hex(rot.getPreviousIncomingKeys().getTagKey().getBytes()));
		out.put("rot_in_next_tag", hex(rot.getNextIncomingKeys().getTagKey().getBytes()));

		byte[] tag = new byte[16];
		tc.encodeTag(tag, key, 4, 3);
		out.put("tag_v4_s3", hex(tag));

		// A whole encrypted stream: tag, stream header, two frames
		byte[] nonce = new byte[24];
		for (int i = 0; i < 24; i++) nonce[i] = (byte) (0x10 + i);
		byte[] frameKeyBytes = new byte[32];
		for (int i = 0; i < 32; i++) frameKeyBytes[i] = (byte) (0xa0 + i);
		ByteArrayOutputStream bytes = new ByteArrayOutputStream();
		byte[] streamTag = new byte[16];
		tc.encodeTag(streamTag, key, 4, 5);
		StreamEncrypterImpl enc = new StreamEncrypterImpl(bytes,
				new XSalsa20Poly1305AuthenticatedCipher(), 5, streamTag, nonce,
				key, new SecretKey(frameKeyBytes));
		enc.writeFrame(A, A.length, 0, false);
		enc.writeFrame(B, B.length, 3, true);
		enc.flush();
		out.put("stream", hex(bytes.toByteArray()));
	}

	/**
	 * Public key for a clamped curve25519 private key. curve25519-java only
	 * generates whole key pairs, so the scalar multiplication comes from
	 * Bouncy Castle -- the same X25519 function, and the agreement below
	 * proves the two agree.
	 */
	public static byte[] pub(byte[] priv) {
		byte[] out = new byte[32];
		org.bouncycastle.math.ec.rfc7748.X25519.scalarMultBase(priv, 0, out, 0);
		return out;
	}

	public static String hex(byte[] b) {
		StringBuilder sb = new StringBuilder();
		for (byte x : b) sb.append(String.format("%02x", x));
		return sb.toString();
	}
}
