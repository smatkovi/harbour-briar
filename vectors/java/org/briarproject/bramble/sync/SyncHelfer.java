package org.briarproject.bramble.sync;

import org.briarproject.bramble.api.crypto.CryptoComponent;
import org.briarproject.bramble.api.sync.GroupFactory;
import org.briarproject.bramble.api.sync.MessageFactory;

/** GroupFactoryImpl und MessageFactoryImpl sind paketprivat -- die Tuer. */
public class SyncHelfer {
	public static GroupFactory gruppen(CryptoComponent crypto) { return new GroupFactoryImpl(crypto); }
	public static MessageFactory nachrichten(CryptoComponent crypto) { return new MessageFactoryImpl(crypto); }
}
