package org.signal.libsignal.metadata.encoding;

import java.util.Map;

/**
 * An implementation of Base32 encoding/decoding that accepts arbitrary alphabets.
 * From http://www.herongyang.com/Encoding/Base32-Bitpedia-Java-Implementation.html;
 *
 * It also supports a replacement table on decoding to handle mis-entered letters.
 */
public class Base32 {
    private final String alphabet;

    private static final int[] base32Lookup = new int[128];
    private static final int[] replacementLookup = new int[128];

    /**
     * Constructs a new non-padded Base32 encoder with a custom alphabet (must be 32 characters).
     *
     * Based on http://www.herongyang.com/Encoding/Base32-Bitpedia-Java-Implementation.html.
     *
     * @param alphabet
     */
    public Base32(String alphabet, Map<Integer, Integer> replacements) {
        if (alphabet.length() != 32) {
            throw new RuntimeException("alphabet is not 32-bytes long");
        }
        this.alphabet = alphabet;
        for (int i = 0; i < base32Lookup.length; i++) {
            base32Lookup[i] = 0xFF;
        }
        for (int i = 0; i < alphabet.length(); i++) {
            base32Lookup[(int) alphabet.charAt(i)] = i;
        }
        for (int i = 0; i < replacementLookup.length; i++) {
            replacementLookup[i] = 0xFF;
        }
        if (replacements != null) {
            for (Map.Entry<Integer, Integer> entry : replacements.entrySet()) {
                replacementLookup[entry.getKey()] = entry.getValue();
            }
        }
    }

    /**
     * Encodes byte array to Base32 String.
     *
     * @param bytes Bytes to encode.
     * @return Encoded byte array <code>bytes</code> as a String.
     *
     */
    public String encodeToString(final byte[] bytes) {
        int i = 0, index = 0, digit = 0;
        int currByte, nextByte;
        StringBuffer base32
                = new StringBuffer((bytes.length + 7) * 8 / 5);

        while (i < bytes.length) {
            currByte = (bytes[i] >= 0) ? bytes[i] : (bytes[i] + 256);

            /* Is the current digit going to span a byte boundary? */
            if (index > 3) {
                if ((i + 1) < bytes.length) {
                    nextByte = (bytes[i + 1] >= 0)
                            ? bytes[i + 1] : (bytes[i + 1] + 256);
                } else {
                    nextByte = 0;
                }

                digit = currByte & (0xFF >> index);
                index = (index + 5) % 8;
                digit <<= index;
                digit |= nextByte >> (8 - index);
                i++;
            } else {
                digit = (currByte >> (8 - (index + 5))) & 0x1F;
                index = (index + 5) % 8;
                if (index == 0)
                    i++;
            }
            base32.append(alphabet.charAt(digit));
        }

        return base32.toString();
    }

    /**
     * Decodes the given Base32 String to a raw byte array.
     *
     * @param base32
     * @return Decoded <code>base32</code> String as a raw byte array.
     */
    public byte[] decodeFromString(final String base32) {
        int i, index, lookup, offset, digit, replacement;
        byte[] bytes = new byte[base32.length() * 5 / 8];

        for (i = 0, index = 0, offset = 0; i < base32.length(); i++) {
            lookup = base32.charAt(i);

            /* Skip chars outside the lookup table */
            if (lookup < 0 || lookup >= base32Lookup.length) {
                continue;
            }

            replacement = replacementLookup[lookup];
            if (replacement != 0xFF) {
                lookup = replacement;
            }

            digit = base32Lookup[lookup];

            /* If this digit is not in the table, ignore it */
            if (digit == 0xFF) {
                continue;
            }

            if (index <= 3) {
                index = (index + 5) % 8;
                if (index == 0) {
                    bytes[offset] |= digit;
                    offset++;
                    if (offset >= bytes.length)
                        break;
                } else {
                    bytes[offset] |= digit << (8 - index);
                }
            } else {
                index = (index + 5) % 8;
                bytes[offset] |= (digit >>> index);
                offset++;

                if (offset >= bytes.length) {
                    break;
                }
                bytes[offset] |= digit << (8 - index);
            }
        }
        return bytes;
    }
}
