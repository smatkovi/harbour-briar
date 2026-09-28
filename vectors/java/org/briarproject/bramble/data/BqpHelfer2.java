package org.briarproject.bramble.data;

import org.briarproject.bramble.api.data.BdfWriterFactory;

/** BdfWriterFactoryImpl ist paketprivat -- hier ist die Tür dazu. */
public class BqpHelfer2 {

	public static BdfWriterFactory schreiber() {
		return new BdfWriterFactoryImpl();
	}
}
