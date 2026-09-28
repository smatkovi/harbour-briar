package org.briarproject.briar.introduction;

import org.briarproject.bramble.api.client.ClientHelper;
import org.briarproject.bramble.api.crypto.AgreementPrivateKey;
import org.briarproject.bramble.api.crypto.AgreementPublicKey;
import org.briarproject.bramble.api.crypto.CryptoComponent;
import org.briarproject.bramble.api.crypto.PrivateKey;
import org.briarproject.bramble.api.crypto.PublicKey;
import org.briarproject.bramble.api.crypto.SecretKey;
import org.briarproject.bramble.api.crypto.SignaturePrivateKey;
import org.briarproject.bramble.api.crypto.SignaturePublicKey;
import org.briarproject.bramble.api.identity.Author;
import org.briarproject.bramble.api.plugin.TransportId;
import org.briarproject.bramble.api.properties.TransportProperties;
import org.briarproject.bramble.api.sync.GroupId;
import org.briarproject.bramble.api.sync.Message;
import org.briarproject.bramble.api.sync.MessageId;
import org.briarproject.bramble.client.ClientHelfer;
import org.briarproject.bramble.api.identity.AuthorFactory;
import org.briarproject.bramble.api.sync.MessageFactory;
import org.briarproject.bramble.identity.IdentitaetHelfer;
import org.briarproject.bramble.sync.SyncHelfer;
import org.briarproject.briar.api.client.SessionId;

import java.util.Map;
import java.util.LinkedHashMap;

import static org.briarproject.bramble.crypto.Vectors.hex;
import static org.briarproject.bramble.crypto.Vectors.newCrypto;
import static org.briarproject.bramble.crypto.Vectors.pub;
import static org.briarproject.briar.api.introduction.IntroductionConstants.LABEL_AUTH_NONCE;
import static org.briarproject.briar.api.introduction.IntroductionManager.CLIENT_ID;
import static org.briarproject.briar.api.introduction.IntroductionManager.MAJOR_VERSION;

/**
 * Referenzbytes fuer das Vorstellen (introduction): Ingrid stellt Anna und
 * Bert einander vor. Alles fest gewaehlt, nichts gewuerfelt -- nur so sind
 * die Werte reproduzierbar und taugen als Vergleich fuer den Port.
 *
 * Liegt in diesem Paket, weil IntroductionCryptoImpl, MessageEncoderImpl und
 * die Sitzungsklassen paketprivat sind.
 */
public class Vectors9 {

	private static byte[] bytes(int start) {
		byte[] b = new byte[32];
		for (int i = 0; i < 32; i++) b[i] = (byte) (start + i);
		return b;
	}

	/** Wie curve25519-java einen privaten Schluessel klammert. */
	private static void klammern(byte[] priv) {
		priv[0] &= 248;
		priv[31] &= 127;
		priv[31] |= 64;
	}

	public static void dump(Map<String, String> out) throws Exception {
		CryptoComponent crypto = newCrypto();
		AuthorFactory af = IdentitaetHelfer.autoren(crypto);
		MessageFactory mf = SyncHelfer.nachrichten(crypto);
		ClientHelper ch = ClientHelfer.bauen(crypto, mf);
		IntroductionCryptoImpl ic = new IntroductionCryptoImpl(crypto, ch);
		MessageEncoderImpl enc = new MessageEncoderImpl(ch, mf);

		Author ingrid = af.createAuthor("Ingrid", new SignaturePublicKey(bytes(0x50)));
		Author anna = af.createAuthor("Anna", new SignaturePublicKey(bytes(0x60)));
		Author bert = af.createAuthor("Bert", new SignaturePublicKey(bytes(0x70)));
		out.put("intro_author_ingrid", hex(ingrid.getId().getBytes()));
		out.put("intro_author_anna", hex(anna.getId().getBytes()));
		out.put("intro_author_bert", hex(bert.getId().getBytes()));

		// Die Kontaktgruppe des Vorstell-Klienten zwischen Anna und Bert.
		GroupId kg = ClientHelfer.kontaktgruppen(SyncHelfer.gruppen(crypto), ch)
				.createContactGroup(CLIENT_ID, MAJOR_VERSION, anna.getId(), bert.getId())
				.getId();
		out.put("intro_contact_group", hex(kg.getBytes()));

		// Sitzungskennung -- aus beiden Blickwinkeln gleich.
		SessionId sidA = ic.getSessionId(ingrid, anna, bert);
		SessionId sidB = ic.getSessionId(ingrid, bert, anna);
		out.put("intro_session_id", hex(sidA.getBytes()));
		out.put("intro_session_id_bob_view", hex(sidB.getBytes()));
		boolean annaAlice = ic.isAlice(anna.getId(), bert.getId());
		out.put("intro_anna_is_alice", annaAlice ? "01" : "00");

		// Fluechtige Schluessel.
		byte[] privA = bytes(0x80); klammern(privA);
		byte[] privB = bytes(0x90); klammern(privB);
		PrivateKey ephPrivA = new AgreementPrivateKey(privA);
		PrivateKey ephPrivB = new AgreementPrivateKey(privB);
		PublicKey ephPubA = new AgreementPublicKey(pub(privA));
		PublicKey ephPubB = new AgreementPublicKey(pub(privB));
		out.put("intro_eph_priv_anna", hex(privA));
		out.put("intro_eph_pub_anna", hex(ephPubA.getEncoded()));
		out.put("intro_eph_priv_bert", hex(privB));
		out.put("intro_eph_pub_bert", hex(ephPubB.getEncoded()));

		SecretKey masterA = ic.deriveMasterKey(ephPubA, ephPrivA, ephPubB, annaAlice);
		SecretKey masterB = ic.deriveMasterKey(ephPubB, ephPrivB, ephPubA, !annaAlice);
		out.put("intro_master_anna_view", hex(masterA.getBytes()));
		out.put("intro_master_bert_view", hex(masterB.getBytes()));
		SecretKey aliceMac = ic.deriveMacKey(masterA, true);
		SecretKey bobMac = ic.deriveMacKey(masterA, false);
		out.put("intro_mac_key_alice", hex(aliceMac.getBytes()));
		out.put("intro_mac_key_bob", hex(bobMac.getBytes()));

		// Adressen und Annahmezeiten.
		Map<TransportId, TransportProperties> propsA = new LinkedHashMap<>();
		TransportProperties lan = new TransportProperties();
		lan.put("ipPorts", "10.0.0.1:7327");
		propsA.put(new TransportId("org.briarproject.bramble.lan"), lan);
		Map<TransportId, TransportProperties> propsB = new LinkedHashMap<>();
		TransportProperties bt = new TransportProperties();
		bt.put("address", "00:11:22:33:44:55");
		propsB.put(new TransportId("org.briarproject.bramble.bluetooth"), bt);
		long tsA = 1700000000000L, tsB = 1700000001000L;

		SecretKey annaMac = annaAlice ? aliceMac : bobMac;
		SecretKey bertMac = annaAlice ? bobMac : aliceMac;
		IntroduceeSession.Local localA = new IntroduceeSession.Local(annaAlice, null, 0,
				ephPubA, ephPrivA, propsA, tsA, annaMac.getBytes());
		IntroduceeSession.Remote remoteB = new IntroduceeSession.Remote(!annaAlice, bert,
				null, ephPubB, propsB, tsB, bertMac.getBytes());
		byte[] authMacA = ic.authMac(annaMac, ingrid.getId(), anna.getId(), localA, remoteB);
		out.put("intro_auth_mac_anna", hex(authMacA));
		// Bert prueft ihn mit vertauschten Seiten -- muss durchgehen.
		ic.verifyAuthMac(authMacA, annaMac, ingrid.getId(), bert.getId(),
				remoteB, anna.getId(), localA);
		out.put("intro_auth_mac_verified", "01");

		byte[] nonce = crypto.mac(LABEL_AUTH_NONCE, annaMac);
		out.put("intro_auth_nonce_anna", hex(nonce));
		byte[] seed = bytes(0x40);
		byte[] sig = ic.sign(annaMac, new SignaturePrivateKey(seed));
		out.put("intro_sig_seed_anna", hex(seed));
		out.put("intro_auth_sig_anna", hex(sig));
		out.put("intro_activate_mac_anna", hex(ic.activateMac(annaMac)));

		// Die sechs Saetze, wie sie ueber die Leitung gehen (nur der Rumpf).
		GroupId g = new GroupId(bytes(0x11));
		MessageId prev = new MessageId(bytes(0x22));
		long t = 1700000002000L;
		Message m;
		m = enc.encodeRequestMessage(g, t, null, bert, "hallo");
		out.put("intro_body_request", hex(m.getBody()));
		m = enc.encodeRequestMessage(g, t, prev, bert, null);
		out.put("intro_body_request_prev_notext", hex(m.getBody()));
		m = enc.encodeRequestMessage(g, t, null, bert, "hallo", 60000L);
		out.put("intro_body_request_timer", hex(m.getBody()));
		m = enc.encodeAcceptMessage(g, t, prev, sidA, ephPubA, tsA, propsA);
		out.put("intro_body_accept", hex(m.getBody()));
		m = enc.encodeDeclineMessage(g, t, prev, sidA);
		out.put("intro_body_decline", hex(m.getBody()));
		m = enc.encodeAuthMessage(g, t, prev, sidA, authMacA, sig);
		out.put("intro_body_auth", hex(m.getBody()));
		m = enc.encodeActivateMessage(g, t, prev, sidA, ic.activateMac(annaMac));
		out.put("intro_body_activate", hex(m.getBody()));
		m = enc.encodeAbortMessage(g, t, prev, sidA);
		out.put("intro_body_abort", hex(m.getBody()));
		out.put("intro_msg_id_request", hex(
				enc.encodeRequestMessage(g, t, null, bert, "hallo").getId().getBytes()));
	}
}
