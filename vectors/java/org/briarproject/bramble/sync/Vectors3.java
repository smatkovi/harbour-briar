package org.briarproject.bramble.sync;

import org.briarproject.bramble.api.crypto.CryptoComponent;
import org.briarproject.bramble.api.sync.ClientId;
import org.briarproject.bramble.api.sync.Group;
import org.briarproject.bramble.api.sync.GroupId;
import org.briarproject.bramble.api.sync.Message;

import java.util.Map;

import static org.briarproject.bramble.crypto.Vectors.hex;
import static org.briarproject.bramble.crypto.Vectors.newCrypto;

/** Group and message identifiers, from the real factories. */
public class Vectors3 {

	public static void dump(Map<String, String> out) throws Exception {
		CryptoComponent crypto = newCrypto();
		GroupFactoryImpl gf = new GroupFactoryImpl(crypto);
		MessageFactoryImpl mf = new MessageFactoryImpl(crypto);

		byte[] descriptor = new byte[] {9, 8, 7};
		Group g = gf.createGroup(
				new ClientId("org.briarproject.briar.messaging"), 0,
				descriptor);
		out.put("group_id", hex(g.getId().getBytes()));
		Group local = gf.createGroup(
				new ClientId("org.briarproject.bramble.versioning"), 0,
				new byte[0]);
		out.put("group_id_local_versioning", hex(local.getId().getBytes()));

		byte[] body = "hallo welt".getBytes("UTF-8");
		Message m = mf.createMessage(g.getId(), 1700000000000L, body);
		out.put("message_id", hex(m.getId().getBytes()));
		out.put("message_raw", hex(mf.getRawMessage(m)));
	}
}
