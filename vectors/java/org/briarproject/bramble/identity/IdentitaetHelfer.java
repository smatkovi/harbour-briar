package org.briarproject.bramble.identity;

import org.briarproject.bramble.api.crypto.CryptoComponent;
import org.briarproject.bramble.api.identity.AuthorFactory;

/** AuthorFactoryImpl ist paketprivat -- die Tuer. */
public class IdentitaetHelfer {
	public static AuthorFactory autoren(CryptoComponent crypto) {
		return new AuthorFactoryImpl(crypto);
	}
}
