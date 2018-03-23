package org.signal.libsignal.metadata;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

import junit.framework.TestCase;

import org.signal.libsignal.metadata.certificate.CertificateValidator;
import org.signal.libsignal.metadata.certificate.InvalidCertificateException;
import org.signal.libsignal.metadata.certificate.SenderCertificate;
import org.signal.libsignal.metadata.certificate.ServerCertificate;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.SessionBuilder;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.UntrustedIdentityException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.util.KeyHelper;
import org.whispersystems.libsignal.util.Pair;

public class SealedSessionCipherTest extends TestCase {

  public void testEncryptDecrypt() throws UntrustedIdentityException, InvalidKeyException, InvalidCertificateException, InvalidProtocolBufferException, InvalidMetadataMessageException, ProtocolDuplicateMessageException, ProtocolUntrustedIdentityException, ProtocolLegacyMessageException, ProtocolInvalidKeyException, InvalidMetadataVersionException, ProtocolInvalidVersionException, ProtocolInvalidMessageException, ProtocolInvalidKeyIdException, ProtocolNoSessionException, SelfSendException {
    TestInMemorySignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
    TestInMemorySignalProtocolStore bobStore   = new TestInMemorySignalProtocolStore();

    initializeSessions(aliceStore, bobStore);

    ECKeyPair           trustRoot         = Curve.generateKeyPair();
    SenderCertificate   senderCertificate = createCertificateFor(trustRoot, "+14151111111", 1, aliceStore.getIdentityKeyPair().getPublicKey().getPublicKey(), 31337);
    SealedSessionCipher aliceCipher       = new SealedSessionCipher(aliceStore, new SignalProtocolAddress("+14151111111", 1));

    byte[] ciphertext = aliceCipher.encrypt(new SignalProtocolAddress("+14152222222", 1),
                                            senderCertificate, "smert za smert".getBytes());


    SealedSessionCipher bobCipher = new SealedSessionCipher(bobStore, new SignalProtocolAddress("+14152222222", 1));

    Pair<SignalProtocolAddress, byte[]> plaintext = bobCipher.decrypt(new CertificateValidator(trustRoot.getPublicKey()), ciphertext, 31335);

    assertEquals(new String(plaintext.second()), "smert za smert");
    assertEquals(plaintext.first().getName(), "+14151111111");
    assertEquals(plaintext.first().getDeviceId(), 1);
  }

  public void testEncryptDecryptUntrusted() throws Exception {
    TestInMemorySignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
    TestInMemorySignalProtocolStore bobStore   = new TestInMemorySignalProtocolStore();

    initializeSessions(aliceStore, bobStore);

    ECKeyPair           trustRoot         = Curve.generateKeyPair();
    ECKeyPair           falseTrustRoot    = Curve.generateKeyPair();
    SenderCertificate   senderCertificate = createCertificateFor(falseTrustRoot, "+14151111111", 1, aliceStore.getIdentityKeyPair().getPublicKey().getPublicKey(), 31337);
    SealedSessionCipher aliceCipher       = new SealedSessionCipher(aliceStore, new SignalProtocolAddress("+14151111111", 1));

    byte[] ciphertext = aliceCipher.encrypt(new SignalProtocolAddress("+14152222222", 1),
                                            senderCertificate, "и вот я".getBytes());

    SealedSessionCipher bobCipher = new SealedSessionCipher(bobStore, new SignalProtocolAddress("+14152222222",1));

    try {
      bobCipher.decrypt(new CertificateValidator(trustRoot.getPublicKey()), ciphertext, 31335);
      throw new AssertionError();
    } catch (InvalidMetadataMessageException e) {
      // good
    }
  }

  public void testEncryptDecryptExpired() throws Exception {
    TestInMemorySignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
    TestInMemorySignalProtocolStore bobStore   = new TestInMemorySignalProtocolStore();

    initializeSessions(aliceStore, bobStore);

    ECKeyPair           trustRoot         = Curve.generateKeyPair();
    SenderCertificate   senderCertificate = createCertificateFor(trustRoot, "+14151111111", 1, aliceStore.getIdentityKeyPair().getPublicKey().getPublicKey(), 31337);
    SealedSessionCipher aliceCipher       = new SealedSessionCipher(aliceStore, new SignalProtocolAddress("+14151111111", 1));

    byte[] ciphertext = aliceCipher.encrypt(new SignalProtocolAddress("+14152222222", 1),
                                            senderCertificate, "и вот я".getBytes());

    SealedSessionCipher bobCipher = new SealedSessionCipher(bobStore, new SignalProtocolAddress("+14152222222", 1));

    try {
      bobCipher.decrypt(new CertificateValidator(trustRoot.getPublicKey()), ciphertext, 31338);
      throw new AssertionError();
    } catch (InvalidMetadataMessageException e) {
      // good
    }
  }

  public void testEncryptFromWrongIdentity() throws Exception {
    TestInMemorySignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
    TestInMemorySignalProtocolStore bobStore   = new TestInMemorySignalProtocolStore();

    initializeSessions(aliceStore, bobStore);

    ECKeyPair           trustRoot         = Curve.generateKeyPair();
    ECKeyPair           randomKeyPair     = Curve.generateKeyPair();
    SenderCertificate   senderCertificate = createCertificateFor(trustRoot, "+14151111111", 1, randomKeyPair.getPublicKey(), 31337);
    SealedSessionCipher aliceCipher       = new SealedSessionCipher(aliceStore, new SignalProtocolAddress("+14151111111", 1));

    byte[] ciphertext = aliceCipher.encrypt(new SignalProtocolAddress("+14152222222", 1),
                                            senderCertificate, "smert za smert".getBytes());


    SealedSessionCipher bobCipher = new SealedSessionCipher(bobStore, new SignalProtocolAddress("+14152222222", 1));

    try {
      bobCipher.decrypt(new CertificateValidator(trustRoot.getPublicKey()), ciphertext, 31335);
    } catch (InvalidMetadataMessageException e) {
      // good
    }
  }



  private SenderCertificate createCertificateFor(ECKeyPair trustRoot, String sender, int deviceId, ECPublicKey identityKey, long expires)
      throws InvalidKeyException, InvalidCertificateException, InvalidProtocolBufferException {
    ECKeyPair serverKey = Curve.generateKeyPair();

    byte[] serverCertificateBytes = SignalProtos.ServerCertificate.Certificate.newBuilder()
                                                                              .setId(1)
                                                                              .setKey(ByteString.copyFrom(serverKey.getPublicKey().serialize()))
                                                                              .build()
                                                                              .toByteArray();

    byte[] serverCertificateSignature = Curve.calculateSignature(trustRoot.getPrivateKey(), serverCertificateBytes);

    ServerCertificate serverCertificate = new ServerCertificate(SignalProtos.ServerCertificate.newBuilder()
                                                                                              .setCertificate(ByteString.copyFrom(serverCertificateBytes))
                                                                                              .setSignature(ByteString.copyFrom(serverCertificateSignature))
                                                                                              .build()
                                                                                              .toByteArray());

    byte[] senderCertificateBytes = SignalProtos.SenderCertificate.Certificate.newBuilder()
                                                                              .setSender(sender)
                                                                              .setSenderDevice(deviceId)
                                                                              .setIdentityKey(ByteString.copyFrom(identityKey.serialize()))
                                                                              .setExpires(expires)
                                                                              .setSigner(SignalProtos.ServerCertificate.parseFrom(serverCertificate.getSerialized()))
                                                                              .build()
                                                                              .toByteArray();

    byte[] senderCertificateSignature = Curve.calculateSignature(serverKey.getPrivateKey(), senderCertificateBytes);

    return new SenderCertificate(SignalProtos.SenderCertificate.newBuilder()
                                                               .setCertificate(ByteString.copyFrom(senderCertificateBytes))
                                                               .setSignature(ByteString.copyFrom(senderCertificateSignature))
                                                               .build()
                                                               .toByteArray());
  }

  private void initializeSessions(TestInMemorySignalProtocolStore aliceStore, TestInMemorySignalProtocolStore bobStore)
      throws InvalidKeyException, UntrustedIdentityException
  {
    ECKeyPair          bobPreKey       = Curve.generateKeyPair();
    IdentityKeyPair    bobIdentityKey  = bobStore.getIdentityKeyPair();
    SignedPreKeyRecord bobSignedPreKey = KeyHelper.generateSignedPreKey(bobIdentityKey, 2);

    PreKeyBundle bobBundle             = new PreKeyBundle(1, 1, 1, bobPreKey.getPublicKey(), 2, bobSignedPreKey.getKeyPair().getPublicKey(), bobSignedPreKey.getSignature(), bobIdentityKey.getPublicKey());
    SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, new SignalProtocolAddress("+14152222222", 1));
    aliceSessionBuilder.process(bobBundle);

    bobStore.storeSignedPreKey(2, bobSignedPreKey);
    bobStore.storePreKey(1, new PreKeyRecord(1, bobPreKey));

  }
}
