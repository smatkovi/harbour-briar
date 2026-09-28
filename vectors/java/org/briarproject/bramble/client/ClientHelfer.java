package org.briarproject.bramble.client;

import org.briarproject.bramble.api.client.ClientHelper;
import org.briarproject.bramble.api.client.ContactGroupFactory;
import org.briarproject.bramble.api.crypto.CryptoComponent;
import org.briarproject.bramble.api.data.BdfReaderFactory;
import org.briarproject.bramble.api.data.BdfWriterFactory;
import org.briarproject.bramble.api.sync.GroupFactory;
import org.briarproject.bramble.api.sync.MessageFactory;
import org.briarproject.bramble.data.BdfHelfer3;
import org.briarproject.bramble.data.BqpHelfer2;
import org.briarproject.bramble.identity.IdentitaetHelfer;

/**
 * ClientHelperImpl ist paketprivat und will eine Datenbank -- die benutzen
 * die Stuecke, die hier gebraucht werden (toList, toDictionary, toByteArray),
 * aber nicht. Also null hinein; der Konstruktor speichert sie nur.
 */
public class ClientHelfer {
	public static ClientHelper bauen(CryptoComponent crypto, MessageFactory mf) {
		BdfReaderFactory r = BdfHelfer3.leser();
		BdfWriterFactory w = BqpHelfer2.schreiber();
		return new ClientHelperImpl(null, mf, r, w, BdfHelfer3.deuter(r),
				BdfHelfer3.kodierer(w), crypto, IdentitaetHelfer.autoren(crypto));
	}
	public static ContactGroupFactory kontaktgruppen(GroupFactory gf, ClientHelper ch) {
		return new ContactGroupFactoryImpl(gf, ch);
	}
}
