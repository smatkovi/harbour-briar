package org.briarproject.bramble.crypto;

import org.briarproject.bramble.api.crypto.CryptoComponent;
import org.briarproject.bramble.api.crypto.KeyAgreementCrypto;

/** KeyAgreementCryptoImpl ist paketprivat -- hier ist die Tür dazu. */
public class BqpHelfer {

	public static KeyAgreementCrypto neu(CryptoComponent crypto) {
		return new KeyAgreementCryptoImpl(crypto);
	}
}
