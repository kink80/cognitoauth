package searchfast.cloud.auth.cognito;

import java.math.BigInteger;

/**
 *  Stores public keys A, B and a session key S
 */
public class AWSClientEvidenceContext extends AWSPasswordAuthContext {

  public final BigInteger S;

  public AWSClientEvidenceContext(BigInteger A, BigInteger B, BigInteger S) {
    super(A, B);
    this.S = S;
  }

}
