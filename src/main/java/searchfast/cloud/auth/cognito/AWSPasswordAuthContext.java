package searchfast.cloud.auth.cognito;

import java.math.BigInteger;

public class AWSPasswordAuthContext {

  public final BigInteger A;
  public final BigInteger B;

  public AWSPasswordAuthContext(BigInteger A, BigInteger B) {
    this.A = A;
    this.B = B;
  }

}
