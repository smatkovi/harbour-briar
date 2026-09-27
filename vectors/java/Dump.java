import java.util.LinkedHashMap;
import java.util.Map;

/** Prints every reference value as key=hex, one per line. */
public class Dump {

	public static void main(String[] args) throws Exception {
		Map<String, String> out = new LinkedHashMap<>();
		org.briarproject.bramble.crypto.Vectors.dump(out);
		org.briarproject.bramble.data.Vectors2.dump(out);
		org.briarproject.bramble.sync.Vectors3.dump(out);
		org.briarproject.bramble.identity.Vectors4.dump(out);
		org.briarproject.bramble.contact.Vectors5.dump(out);
		org.briarproject.bramble.rendezvous.Vectors6.dump(out);
		org.briarproject.bramble.plugin.tor.Vectors7.dump(out);
		for (Map.Entry<String, String> e : out.entrySet())
			System.out.println(e.getKey() + "=" + e.getValue());
	}
}
