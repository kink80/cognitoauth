package searchfast.cloud.auth.cognito;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * Computes device evidence context based on device key and group key
 */
public class AWSDeviceEvidenceContext {

  public static String SALT_PARAMETER = "salt";
  public static String VERIFIER_PARAMETER = "verifier";
  public static String SECRET_PARAMETER = "secret";

  private final AWSCryptoSettings cryptoSettings;

  public AWSDeviceEvidenceContext(AWSCryptoSettings cryptoSettings) {
    this.cryptoSettings = cryptoSettings;
  }

  public AWSDeviceContext getDeviceContext(String deviceKey, String deviceGroupKey) {
    String deviceSecret = cryptoSettings.generateRandomString();
    final byte[] deviceKeyHash = getUserIdHash(deviceGroupKey, deviceKey, deviceSecret);
    byte[] salt = cryptoSettings.randomBigInteger().toByteArray();
    byte[] srpVerifier = generateVerifier(salt, deviceKeyHash).toByteArray();

    AWSDeviceContext deviceContext = new AWSDeviceContext(new String(Base64.getEncoder().encode(srpVerifier)),
                                                          new String(Base64.getEncoder().encode(salt)),
                                                          deviceSecret);
    return deviceContext;
  }

  private byte[] getUserIdHash(String poolName, String userName, String password) {
    MessageDigest md = cryptoSettings.getMessageDigestInstance();
    md.reset();

    List<String> hashedParts = Arrays.asList(new String[] { poolName, userName, ":", password});
    hashedParts.forEach(p -> {
      if (p != null) {
        md.update(p.getBytes(StandardCharsets.UTF_8));
      }
    });

    return md.digest();
  }

  private BigInteger generateVerifier(byte[] salt, byte[] userIdHash) {
    MessageDigest md = cryptoSettings.getMessageDigestInstance();
    md.reset();

    md.update(salt);
    md.update(userIdHash);

    final byte[] digest = md.digest();
    final BigInteger x = new BigInteger(1, digest);
    return AWSCryptoSettings.g.modPow(x, AWSCryptoSettings.N);
  }
}
