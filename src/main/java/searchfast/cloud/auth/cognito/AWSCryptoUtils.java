package searchfast.cloud.auth.cognito;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 *  SRP utility methods
 *  - compute private key a
 *  - compute public key A from a
 *  - compute multiplier k
 *  - compute session key S
 */
public class AWSCryptoUtils {

  private final SecureRandom random = new SecureRandom();
  private final AWSCryptoSettings settings;

  public AWSCryptoUtils(AWSCryptoSettings settings) {
    this.settings = settings;
  }

  public BigInteger computeSessionKey(final BigInteger k,
                                      final BigInteger x,
                                      final BigInteger u,
                                      final BigInteger a,
                                      final BigInteger B) {

    final BigInteger exp = u.multiply(x).add(a);
    final BigInteger tmp = settings.g.modPow(x, settings.N).multiply(k);
    return B.subtract(tmp).modPow(exp, settings.N);
  }

  /**
   * Computes multiplier, k = H(N, g)
   */
  public BigInteger computeK() {
    MessageDigest messageDigest = settings.getMessageDigestInstance();
    messageDigest.update(settings.N.toByteArray());
    byte[] digest = messageDigest.digest(settings.g.toByteArray());

    return new BigInteger(1, digest);
  }

  /**
   *
   */
  public BigInteger computeEphemeralKey(BigInteger privateKey) {
    return settings.g.modPow(privateKey, settings.N);
  }

  /**
   * Creates random private key a
   */
  public BigInteger generatePrivateKey() {

    final int minBits = Math.min(256, settings.N.bitLength() / 2);

    BigInteger min = BigInteger.ONE.shiftLeft(minBits - 1);
    BigInteger max = settings.N.subtract(BigInteger.ONE);

    return createRandomBigIntegerInRange(min, max, random);
  }

  private static BigInteger createRandomBigIntegerInRange(final BigInteger min,
                                                     final BigInteger max,
                                                     final SecureRandom random) {

    final int cmp = min.compareTo(max);

    if (cmp >= 0) {

      if (cmp > 0)
        throw new IllegalArgumentException("'min' may not be greater than 'max'");

      return min;
    }

    if (min.bitLength() > max.bitLength() / 2)
      return createRandomBigIntegerInRange(BigInteger.ZERO, max.subtract(min), random).add(min);

    final int MAX_ITERATIONS = 1000;

    for (int i = 0; i < MAX_ITERATIONS; ++i) {

      BigInteger x = new BigInteger(max.bitLength(), random);

      if (x.compareTo(min) >= 0 && x.compareTo(max) <= 0)
        return x;
    }

    return new BigInteger(max.subtract(min).bitLength() - 1, random).add(min);
  }

}
