package org.signal.libsignal.metadata.encoding;

import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECPublicKey;

import java.util.HashMap;
import java.util.Map;

// UserId provides functions for encoding and decoding user Ids to/from strings and to/from
// ECPublicKeys.
public class UserId {
    // This alphabet is based on the z-base-32 alphabet which preferences characters that are easier
    // for humans to read. It omits the number 0 and the letters i, l and v. On decoding, we also
    // map the letters i and l to the number 1 and the number 0 to the letter o.
    private static final String alphabet = "ybndrfg8ejkmcpqxot1uw2sza345h769";
    private static final Map<Integer, Integer> replacements = new HashMap<Integer, Integer>();
    static {
        // map some commonly fat-fingered characters to their correct replacements
        replacements.put((int) 'i', (int) '1');
        replacements.put((int) 'l', (int) '1');
        replacements.put((int) '0', (int) 'o');
    }
    private static final Base32 base32 = new Base32(alphabet, replacements);

    public static String encodeToString(byte[] userId) {
        return base32.encodeToString(userId);
    }

    public static byte[] decodeFromString(String userId) {
        return base32.decodeFromString(userId.toLowerCase());
    }

    public static ECPublicKey keyFrom(byte[] userId) throws InvalidKeyException {
        return Curve.decodePoint(userId, 0);
    }
}