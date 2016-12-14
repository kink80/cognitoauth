package searchfast.cloud.auth.cognito;

import java.math.BigInteger;
import java.security.MessageDigest;

/**
 * Public keys hash routine
 */
public class AWSPasswordScramblingRoutine {

  private final AWSCryptoSettings config;

  public AWSPasswordScramblingRoutine(AWSCryptoSettings config) {
    this.config = config;
  }

  /**
   * Computes random scrambling parameter
   *  u = H(A, B)
   */
  public BigInteger computeHash(AWSPasswordAuthContext ctx) {
    MessageDigest messageDigest = config.getMessageDigestInstance();
    messageDigest.update(ctx.A.toByteArray());
    BigInteger u = new BigInteger(1, messageDigest.digest(ctx.B.toByteArray()));
    if (u.equals(BigInteger.ZERO)) {
      throw new IllegalStateException("Hash of A and B cannot be zero");
    }

    return u;
  }

}
