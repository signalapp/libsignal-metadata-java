package org.signal.libsignal.metadata.encoding;


import junit.framework.TestCase;

import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;

import java.util.Arrays;

public class UserIdTest extends TestCase {

    public void testUserId() throws Exception {
        String string = "y2ft5r9fa3jodumzxhjcdftw3drefxznb8axg5oc4682genn1zmy1";
        String stringWithIAndLAndO = "y2ft5r9fa3j0dumzxhjcdftw3drefxznb8axg5oc4682gennizmyl";

        String roundTrippedUserId = UserId.encodeToString(UserId.decodeFromString(string));
        String roundTrippedFatFingeredUserId = UserId.encodeToString(UserId.decodeFromString(stringWithIAndLAndO.toUpperCase()));
        assertEquals(string, roundTrippedUserId);
        assertEquals(string, roundTrippedFatFingeredUserId);
    }
}