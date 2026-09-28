package org.briarproject.bramble.keyagreement;

import org.briarproject.bramble.api.crypto.AgreementPrivateKey;
import org.briarproject.bramble.api.crypto.AgreementPublicKey;
import org.briarproject.bramble.api.crypto.CryptoComponent;
import org.briarproject.bramble.api.crypto.KeyAgreementCrypto;
import org.briarproject.bramble.api.crypto.KeyPair;
import org.briarproject.bramble.api.crypto.SecretKey;
import org.briarproject.bramble.api.data.BdfList;
import org.briarproject.bramble.api.keyagreement.Payload;
import org.briarproject.bramble.api.keyagreement.TransportDescriptor;
import org.briarproject.bramble.api.plugin.TransportId;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.briarproject.bramble.crypto.Vectors.hex;
import static org.briarproject.bramble.crypto.Vectors.pub;

/**
 * Referenzbytes für BQP -- Briars Verfahren, zwei Geräte nebeneinander
 * zusammenzubringen (Bramble QR Code Protocol).
 *
 * Liegt in diesem Paket, weil PayloadEncoderImpl paketprivat ist. Die beiden
 * anderen paketprivaten Stücke kommen über kleine Helfer in ihren eigenen
 * Paketen herein.
 *
 * Feste Schlüssel statt gewürfelter: nur so sind die Werte reproduzierbar und
 * taugen als Vergleich für den Port.
 */
public class Vectors8 {

	private static final String LAN = "org.briarproject.bramble.lan";
	private static final String BT = "org.briarproject.bramble.bluetooth";

	/** Wie curve25519-java einen privaten Schluessel klammert. */
	private static void klammern(byte[] priv) {
		priv[0] &= 248;
		priv[31] &= 127;
		priv[31] |= 64;
	}

	public static void dump(Map<String, String> out) throws Exception {
		CryptoComponent crypto =
				org.briarproject.bramble.crypto.Vectors.newCrypto();
		KeyAgreementCrypto kac =
				org.briarproject.bramble.crypto.BqpHelfer.neu(crypto);

		// Zwei feste Schlüsselpaare: 0x01.. für Alice, 0x40.. für Bob.
		byte[] alicePriv = new byte[32];
		byte[] bobPriv = new byte[32];
		for (int i = 0; i < 32; i++) {
			alicePriv[i] = (byte) (i + 1);
			bobPriv[i] = (byte) (0x40 + i);
		}
		// Geklammert, wie Briars Schluesselerzeugung es tut
		// (curve25519-java generatePrivateKey). Briars Einigung klammert NICHT
		// nach -- sie rechnet mit dem Skalar, den sie bekommt. Ungeklammerte
		// Testschluessel ergaeben also Werte, die kein echtes Geraet je sieht.
		klammern(alicePriv);
		klammern(bobPriv);
		KeyPair alice = new KeyPair(new AgreementPublicKey(pub(alicePriv)),
				new AgreementPrivateKey(alicePriv));
		KeyPair bob = new KeyPair(new AgreementPublicKey(pub(bobPriv)),
				new AgreementPrivateKey(bobPriv));
		out.put("bqp_alice_priv", hex(alicePriv));
		out.put("bqp_bob_priv", hex(bobPriv));
		out.put("bqp_alice_public", hex(alice.getPublic().getEncoded()));
		out.put("bqp_bob_public", hex(bob.getPublic().getEncoded()));

		// Die Verpflichtung: die ersten 16 Byte des Hashes über den
		// öffentlichen Schlüssel. Sie steht im QR-Code, und an ihr erkennt die
		// Gegenseite, dass der später geschickte Schlüssel derselbe ist.
		byte[] aliceCommit = kac.deriveKeyCommitment(alice.getPublic());
		byte[] bobCommit = kac.deriveKeyCommitment(bob.getPublic());
		out.put("bqp_alice_commit", hex(aliceCommit));
		out.put("bqp_bob_commit", hex(bobCommit));

		// Der QR-Rumpf: ein Kennbyte, dann eine BDF-Liste aus Verpflichtung
		// und Transportbeschreibern.
		PayloadEncoderImpl encoder = new PayloadEncoderImpl(
				org.briarproject.bramble.data.BqpHelfer2.schreiber());
		List<TransportDescriptor> aliceTs = new ArrayList<>();
		BdfList lan = new BdfList();
		lan.add(1);
		lan.add(new byte[] {(byte) 192, (byte) 168, 1, 20});
		lan.add(39000);
		aliceTs.add(new TransportDescriptor(new TransportId(LAN), lan));
		BdfList bt = new BdfList();
		bt.add(0);
		bt.add(new byte[] {(byte) 0x40, (byte) 0x98, (byte) 0x4e,
				(byte) 0xad, (byte) 0xbd, (byte) 0x42});
		aliceTs.add(new TransportDescriptor(new TransportId(BT), bt));
		Payload alicePayload = new Payload(aliceCommit, aliceTs);
		byte[] aliceEncoded = encoder.encode(alicePayload);
		out.put("bqp_alice_payload", hex(aliceEncoded));

		List<TransportDescriptor> bobTs = new ArrayList<>();
		BdfList bobLan = new BdfList();
		bobLan.add(1);
		bobLan.add(new byte[] {(byte) 192, (byte) 168, 1, 21});
		bobLan.add(39001);
		bobTs.add(new TransportDescriptor(new TransportId(LAN), bobLan));
		Payload bobPayload = new Payload(bobCommit, bobTs);
		byte[] bobEncoded = encoder.encode(bobPayload);
		out.put("bqp_bob_payload", hex(bobEncoded));

		// Das gemeinsame Geheimnis, aus Alices Sicht gerechnet: der
		// Fassungsbyte, dann Alices und Bobs öffentlicher Schlüssel.
		byte[][] inputs = {
				new byte[] {4}, // PROTOCOL_VERSION
				alice.getPublic().getEncoded(),
				bob.getPublic().getEncoded()
		};
		SecretKey shared = crypto.deriveSharedSecret(
				"org.briarproject.bramble.keyagreement/SHARED_SECRET",
				bob.getPublic(), alice, inputs);
		out.put("bqp_shared", hex(shared.getBytes()));
		out.put("bqp_master", hex(crypto.deriveKey(
				"org.briarproject.bramble.keyagreement/MASTER_SECRET",
				shared).getBytes()));

		// Die beiden Bestätigungen -- erst Alices, dann Bobs.
		out.put("bqp_confirm_alice", hex(kac.deriveConfirmationRecord(shared,
				bobEncoded, aliceEncoded, bob.getPublic(), alice, true, true)));
		out.put("bqp_confirm_bob", hex(kac.deriveConfirmationRecord(shared,
				bobEncoded, aliceEncoded, bob.getPublic(), alice, true, false)));
	}
}
