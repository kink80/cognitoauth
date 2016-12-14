package searchfast.cloud.auth.cognito;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;

/**
 * Computes client evidence key as expected by Cognito Idenity Pool
 */
public class AWSClientEvidenceRoutine {

  private static final int DERIVED_KEY_SIZE = 16;
  private static final byte[] DERIVED_KEY_INFO = "Caldera Derived Key".getBytes(StandardCharsets.UTF_8);

  private final AWSCryptoSettings settings;
  private final AWSPasswordScramblingRoutine hashedKeysRoutine;

  public AWSClientEvidenceRoutine(AWSCryptoSettings cryptoSettings,
                                  AWSPasswordScramblingRoutine hashedKeysRoutine) {
    this.settings = cryptoSettings;
    this.hashedKeysRoutine = hashedKeysRoutine;
  }

  public byte[] computeClientEvidenceKey(AWSClientEvidenceContext ctx) {
    byte[] result = new byte[DERIVED_KEY_SIZE];
    try {
      Mac mac = settings.getMacInstance();

      BigInteger u = hashedKeysRoutine.computeHash(new AWSPasswordAuthContext(ctx.A, ctx.B));
      byte[] scramble = u.toByteArray();

      mac.init(new SecretKeySpec(scramble, mac.getAlgorithm()));
      byte[] raw = mac.doFinal(ctx.S.toByteArray());

      SecretKeySpec secretKey = new SecretKeySpec(raw, mac.getAlgorithm());

      Mac ex = settings.getMacInstance();
      ex.init(secretKey);

      byte[] t = new byte[0];
      int loc = 0;

      for(byte i = 1; loc < DERIVED_KEY_SIZE; ++i) {
        ex.update(t);
        ex.update(DERIVED_KEY_INFO);
        ex.update(i);
        t = ex.doFinal();

        for(int x = 0; x < t.length && loc < DERIVED_KEY_SIZE; ++loc) {
          result[loc] = t[x];
          ++x;
        }
      }
    } catch (InvalidKeyException e) {
      throw new IllegalArgumentException(e);
    }

    return result;
  }

}
