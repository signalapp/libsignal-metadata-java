package org.signal.libsignal.metadata;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

import junit.framework.TestCase;

import org.signal.libsignal.metadata.SealedSessionCipher.DecryptionResult;
import org.signal.libsignal.metadata.certificate.InvalidCertificateException;
import org.signal.libsignal.metadata.certificate.SenderCertificate;
import org.signal.libsignal.metadata.encoding.UserId;
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
import org.whispersystems.libsignal.util.Hex;
import org.whispersystems.libsignal.util.KeyHelper;
import org.whispersystems.libsignal.util.Pair;

import java.io.IOException;
import java.util.UUID;

public class SealedSessionCipherTest extends TestCase {
  private static final int staticDeviceId = 1;

  public void testEncryptDecryptSuccess() throws Exception {
    TestInMemorySignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
    TestInMemorySignalProtocolStore bobStore   = new TestInMemorySignalProtocolStore();

    String aliceUserId = UserId.encodeToString(aliceStore.getIdentityKeyPair().getPublicKey().serialize());
    SignalProtocolAddress aliceAddress = new SignalProtocolAddress(aliceUserId, staticDeviceId);
    String bobUserId = UserId.encodeToString(bobStore.getIdentityKeyPair().getPublicKey().serialize());
    SignalProtocolAddress bobAddress = new SignalProtocolAddress(bobUserId, staticDeviceId);

    initializeSessions(aliceStore, bobStore);

    ECKeyPair           trustRoot         = Curve.generateKeyPair();
    SealedSessionCipher aliceCipher       = new SealedSessionCipher(aliceStore, UserId.decodeFromString(aliceUserId), staticDeviceId);
    byte[] ciphertext = aliceCipher.encrypt(bobAddress, "smert za smert".getBytes());

    SealedSessionCipher bobCipher = new SealedSessionCipher(bobStore, bobStore.getIdentityKeyPair().getPublicKey().serialize(), staticDeviceId);
    DecryptionResult plaintext = bobCipher.decrypt(ciphertext);
    assertEquals(new String(plaintext.getPaddedMessage()), "smert za smert");
    assertEquals(plaintext.getSenderAddress(), aliceAddress);
  }

  private void initializeSessions(TestInMemorySignalProtocolStore aliceStore, TestInMemorySignalProtocolStore bobStore)
      throws InvalidKeyException, UntrustedIdentityException
  {
    int bobRegistrationId              = 1;
    int bobSignedPreKeyId              = 2;
    int bobPreKeyId                    = 1;
    ECKeyPair          bobPreKey       = Curve.generateKeyPair();
    IdentityKeyPair    bobIdentityKey  = bobStore.getIdentityKeyPair();
    SignedPreKeyRecord bobSignedPreKey = KeyHelper.generateSignedPreKey(bobIdentityKey, bobSignedPreKeyId);

    String bobId = UserId.encodeToString(bobStore.getIdentityKeyPair().getPublicKey().serialize());

    PreKeyBundle bobBundle             = new PreKeyBundle(bobRegistrationId, staticDeviceId, bobPreKeyId, bobPreKey.getPublicKey(), bobSignedPreKeyId, bobSignedPreKey.getKeyPair().getPublicKey(), bobSignedPreKey.getSignature(), bobIdentityKey.getPublicKey());
    SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, new SignalProtocolAddress(bobId, staticDeviceId));
    aliceSessionBuilder.process(bobBundle);

    bobStore.storeSignedPreKey(bobSignedPreKeyId, bobSignedPreKey);
    bobStore.storePreKey(bobPreKeyId, new PreKeyRecord(bobPreKeyId, bobPreKey));

  }
}
