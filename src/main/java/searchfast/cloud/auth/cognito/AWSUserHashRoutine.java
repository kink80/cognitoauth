package searchfast.cloud.auth.cognito;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.SimpleTimeZone;

/**
 * User hashing functions
 *  - provides x hashing routine (x = H(salt | H(poolName | userId | ":" | password)))
 *  - provides challenge digest routine
 */
public class AWSUserHashRoutine {

  private final String username;
  private final String password;
  private final String poolName;
  private final AWSCryptoSettings config;
  private final SimpleDateFormat simpleDateFormat;

  public AWSUserHashRoutine(AWSCryptoSettings config,
                            String username,
                            String password,
                            String userPoolId) {
    this.config = config;
    this.username = username;
    this.password = password;
    this.poolName = userPoolId.split("_", 2)[ 1 ];

    this.simpleDateFormat = new SimpleDateFormat("EEE MMM d HH:mm:ss z yyyy", Locale.US);
    this.simpleDateFormat.setTimeZone(new SimpleTimeZone(SimpleTimeZone.UTC_TIME, "UTC"));
  }

  /**
   * Computes user hash routine based on provided salt valute
   */
  public BigInteger computeUserHash(byte[] salt) {
    MessageDigest messageDigest = config.getMessageDigestInstance();
    messageDigest.update(poolName.getBytes(StandardCharsets.UTF_8));
    messageDigest.update(username.getBytes(StandardCharsets.UTF_8));
    messageDigest.update(":".getBytes(StandardCharsets.UTF_8));

    byte [] userIdHash = messageDigest.digest(password.getBytes(StandardCharsets.UTF_8));
    messageDigest.reset();
    messageDigest.update(salt);

    return new BigInteger(1, messageDigest.digest(userIdHash));
  }

  /**
   * Computes hashed user challenge response that is going to be
   * encrypted by the provided key and passing back the secret block string
   */
  public Map<String, String> computeChallengeResponse(byte[] key, String secretBlockString) {
    Mac mac = config.getMacInstance();
    SecretKeySpec keySpec = new SecretKeySpec(key, mac.getAlgorithm());
    try {
      mac.init(keySpec);

      mac.update(poolName.getBytes(StandardCharsets.UTF_8));
      mac.update(username.getBytes(StandardCharsets.UTF_8));

      byte[] secretBlock = Base64.getDecoder().decode(secretBlockString);
      mac.update(secretBlock);

      String dateString = simpleDateFormat.format(new Date());
      byte[] hmac = mac.doFinal(dateString.getBytes(StandardCharsets.UTF_8));

      Map<String, String> responses = new HashMap<>();
      responses.put("PASSWORD_CLAIM_SECRET_BLOCK", secretBlockString);
      responses.put("PASSWORD_CLAIM_SIGNATURE", new String(Base64.getEncoder().encode(hmac), StandardCharsets.UTF_8));
      responses.put("TIMESTAMP", dateString);
      responses.put("USERNAME", username);

      return responses;
    } catch (InvalidKeyException e) {
       throw new IllegalStateException(e);
    }
  }

}
