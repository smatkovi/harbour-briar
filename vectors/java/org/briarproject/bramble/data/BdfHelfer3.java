package org.briarproject.bramble.data;

import org.briarproject.bramble.api.data.BdfReaderFactory;
import org.briarproject.bramble.api.data.BdfWriterFactory;
import org.briarproject.bramble.api.data.MetadataEncoder;
import org.briarproject.bramble.api.data.MetadataParser;

/** Die drei uebrigen paketprivaten Fabriken aus bramble.data -- die Tuer. */
public class BdfHelfer3 {
	public static BdfReaderFactory leser() { return new BdfReaderFactoryImpl(); }
	public static MetadataParser deuter(BdfReaderFactory r) { return new MetadataParserImpl(r); }
	public static MetadataEncoder kodierer(BdfWriterFactory w) { return new MetadataEncoderImpl(w); }
}
