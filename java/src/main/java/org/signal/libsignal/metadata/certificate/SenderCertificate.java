package org.signal.libsignal.metadata.certificate;


import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

import org.signal.libsignal.metadata.SignalProtos;
import org.signal.libsignal.metadata.encoding.UserId;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECPrivateKey;
import org.whispersystems.libsignal.ecc.ECPublicKey;

/**
 * SenderCertificate represents the address of a sender (userId + deviceId) along with an associated
 * signature of the address. The userId is also the public key with which the signature was generated.
 */
public class SenderCertificate {

  private final byte[] serialized;
  private final byte[] signature;
  private final byte[] userId; // 64 bytes
  private final int deviceId;

  /**
   * Constructs a new SenderCertificate from its serialized representation.
   *
   * @param serialized
   * @throws InvalidCertificateException if there was a problem deserializing the certificate
   * @throws InvalidKeyException if the certificate's signature doesn't match what's expected based on using the userId as the public key
   */
  public SenderCertificate(byte[] serialized) throws InvalidCertificateException, InvalidKeyException {
    try {
      SignalProtos.SenderCertificate wrapper = SignalProtos.SenderCertificate.parseFrom(serialized);

      if (!wrapper.hasSignature() || !wrapper.hasAddress()) {
        throw new InvalidCertificateException("Missing fields");
      }

      SignalProtos.SenderCertificate.Address address = SignalProtos.SenderCertificate.Address.parseFrom(wrapper.getAddress());

      if (!address.hasUserId() || !address.hasDeviceId()) {
        throw new InvalidCertificateException("Missing fields");
      }

      this.userId   = address.getUserId().toByteArray();
      this.deviceId = address.getDeviceId();

      this.serialized  = serialized;
      this.signature   = wrapper.getSignature().toByteArray();

      // Using the userId as the public key, verify that the signature matches the content (deviceId and userId).
      ECPublicKey publicKey = UserId.keyFrom(this.userId);
      if (!Curve.verifySignature(publicKey, address.toByteArray(), this.signature)) {
        throw new InvalidCertificateException("signature verification failed");
      };
    } catch (InvalidProtocolBufferException | InvalidKeyException e) {
      throw new InvalidCertificateException(e);
    }
  }

  public SenderCertificate(byte[] userId, int deviceId, ECPrivateKey signingKey) throws InvalidKeyException {
    byte[] address = SignalProtos.SenderCertificate.Address.newBuilder()
            .setUserId(ByteString.copyFrom(userId))
            .setDeviceId(deviceId)
            .build().toByteArray();
    this.signature = Curve.calculateSignature(signingKey, address);
    this.serialized = SignalProtos.SenderCertificate.newBuilder()
            .setAddress(ByteString.copyFrom(address))
            .setSignature(ByteString.copyFrom(this.signature))
            .build().toByteArray();
    this.userId = userId;
    this.deviceId = deviceId;
  }

  public byte[] getSerialized() {
    return serialized;
  }

  public byte[] getSignature() {
    return signature;
  }

  public byte[] getUserId() {
    return userId;
  }

  public String getSender() {
    return UserId.encodeToString(userId);
  }

  public int getSenderDeviceId() {
    return deviceId;
  }

  public SignalProtocolAddress getSenderAddress() {
    return new SignalProtocolAddress(getSender(), deviceId);
  }
}
