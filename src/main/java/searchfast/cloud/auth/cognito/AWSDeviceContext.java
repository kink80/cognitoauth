package searchfast.cloud.auth.cognito;

/**
 * Stores device's password, salt and secret
 */
public class AWSDeviceContext {

  private final String passwordVerifier;
  private final String salt;
  private final String secret;

  public AWSDeviceContext(String passwordVerifier, String salt, String secret) {
    this.passwordVerifier = passwordVerifier;
    this.salt = salt;
    this.secret = secret;
  }

  public String getPasswordVerifier() {
    return passwordVerifier;
  }

  public String getSalt() {
    return salt;
  }

  public String getSecret() {
    return secret;
  }

}
