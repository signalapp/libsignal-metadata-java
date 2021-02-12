package org.signal.libsignal.metadata.certificate;


import junit.framework.TestCase;

import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;

public class SenderCertificateTest extends TestCase {

  public void testGoodSignature() throws InvalidCertificateException, InvalidKeyException {
    ECKeyPair key       = Curve.generateKeyPair();

    byte[] userId = key.getPublicKey().serialize();
    int deviceId = 1;
    SenderCertificate certificate = new SenderCertificate(userId, deviceId, key.getPrivateKey());
    byte[] serialized = certificate.getSerialized();
    SenderCertificate roundTripped = new SenderCertificate(serialized);
    assertEquals(certificate.getSenderAddress(), roundTripped.getSenderAddress());
  }

  public void testBadSignature() throws InvalidCertificateException, InvalidKeyException {
    ECKeyPair key       = Curve.generateKeyPair();

    byte[] userId = key.getPublicKey().serialize();
    int deviceId = 1;
    SenderCertificate certificate = new SenderCertificate(userId, deviceId, key.getPrivateKey());

    // serialize and mess with signature
    byte[] serialized = certificate.getSerialized();
    serialized[40] += 1;
    try {
      SenderCertificate roundTripped = new SenderCertificate(serialized);
      fail("deserializing certificate with invalid signature should have failed");
    } catch (InvalidCertificateException e) {
      // expected
    }
  }

  public void testBadUserId() throws InvalidCertificateException, InvalidKeyException {
    ECKeyPair key       = Curve.generateKeyPair();

    byte[] userId = key.getPublicKey().serialize();
    int deviceId = 1;
    SenderCertificate certificate = new SenderCertificate(userId, deviceId, key.getPrivateKey());

    // serialize and mess with userId (public key)
    byte[] serialized = certificate.getSerialized();
    serialized[92] += 1;
    try {
      SenderCertificate roundTripped = new SenderCertificate(serialized);
      fail("deserializing certificate with invalid userId should have failed");
    } catch (InvalidCertificateException e) {
      // expected
    }
  }
}