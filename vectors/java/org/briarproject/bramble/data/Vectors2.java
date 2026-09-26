package org.briarproject.bramble.data;

import org.briarproject.bramble.api.data.BdfDictionary;
import org.briarproject.bramble.api.data.BdfList;

import java.io.ByteArrayOutputStream;
import java.util.Map;

import static org.briarproject.bramble.crypto.Vectors.hex;

/** BDF reference encodings, from the real writer. */
public class Vectors2 {

	public static byte[] toBytes(Object o) throws Exception {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		BdfWriterImpl w = new BdfWriterImpl(out);
		if (o instanceof BdfList) w.writeList((BdfList) o);
		else w.writeDictionary((BdfDictionary) o);
		w.flush();
		return out.toByteArray();
	}

	private static BdfDictionary dict() {
		// Keys deliberately out of order: the writer sorts them
		BdfDictionary d = new BdfDictionary();
		d.put("b", true);
		d.put("a", null);
		d.put("c", "text");
		return d;
	}

	public static void dump(Map<String, String> out) throws Exception {
		out.put("bdf_simple", hex(toBytes(BdfList.of(1, "hallo", new byte[] {1, 2, 3}))));
		out.put("bdf_nested", hex(toBytes(BdfList.of(
				BdfList.of(0L, 127L, 128L, 32768L, -1L, 2147483648L),
				dict(),
				BdfList.of()))));
		out.put("bdf_text", hex(toBytes(BdfList.of("Grüße, Briar"))));
	}
}
