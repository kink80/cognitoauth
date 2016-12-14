package searchfast.cloud.auth.cognito;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

/**
 * This class provides necessary method to login
 * a Cognito user into the system in two steps by usging SRP protocol.
 *
 * 1. Step sends user's name, password, pool id and ephemeral key to the server
 *    Properties in the same order that are being sent to the server are
 *    - USERNAME
 *    - PASSWORD
 *    - SRP_A
 *    - UserPoolId
 * 2. Step expects to compute response challenge based on parameters sent
 * by the server. Expected keys are
 *    - SRP_B
 *    - SALT
 *    - SECRET_BLOCK
 *
 * The response from the second steps contains following keys
 *    - PASSWORD_CLAIM_SECRET_BLOCK
 *    - PASSWORD_CLAIM_SIGNATURE
 *    - TIMESTAMP
 *    - USERNAME
 */
public class AWSCognitoSession {

    // Private key
    private BigInteger a;
    // Public key
    private BigInteger A;
    // Multiplier
    private BigInteger k;

    private String username;
    private String password;
    private String poolId;

    private AWSUserHashRoutine userHashRoutine;
    private AWSClientEvidenceRoutine clientEvidenceRoutine;
    private AWSPasswordScramblingRoutine passwordScramblingRoutine;

    private final AWSCryptoUtils cryptoUtils;

    public AWSCognitoSession(AWSCryptoSettings cryptoParams,
                             String username,
                             String password,
                             String poolId) {
        this.username = username;
        this.password = password;
        this.poolId = poolId;

        this.passwordScramblingRoutine = new AWSPasswordScramblingRoutine(cryptoParams);
        this.userHashRoutine = new AWSUserHashRoutine(cryptoParams, username, password, poolId);
        this.clientEvidenceRoutine = new AWSClientEvidenceRoutine(cryptoParams, passwordScramblingRoutine);
        this.cryptoUtils = new AWSCryptoUtils(cryptoParams);

        // Generate client private key, ephemeral and multiplier
        a = cryptoUtils.generatePrivateKey();
        A = cryptoUtils.computeEphemeralKey(a);
        k = cryptoUtils.computeK();
    }

    public synchronized Map<String, String> step1() {
        Map<String, String> authParameters = new HashMap<>();
        authParameters.put("USERNAME", username);
        authParameters.put("PASSWORD", password);
        authParameters.put("SRP_A", A.toString(16));
        authParameters.put("UserPoolId", poolId);

        return authParameters;
    }

    public synchronized Map<String, String> step2(Map<String, String> params) {
        BigInteger B = new BigInteger(params.get("SRP_B"), 16);
        BigInteger salt = new BigInteger(params.get("SALT"), 16);
        String secretBlockString = params.get("SECRET_BLOCK");

        // Compute random scrambling parameter
        // u = H(A, B)
        BigInteger u = passwordScramblingRoutine.computeHash(new AWSPasswordAuthContext(A, B));

        // Compute  session key
        // x = H(salt | H(poolName | userId | ":" | password))
        BigInteger x = userHashRoutine.computeUserHash(salt.toByteArray());
        BigInteger S = cryptoUtils.computeSessionKey(k, x, u, a, B);

        // Compute proof of session
        AWSClientEvidenceContext ctx = new AWSClientEvidenceContext(A, B, S);
        byte[] key = clientEvidenceRoutine.computeClientEvidenceKey(ctx);

        return userHashRoutine.computeChallengeResponse(key, secretBlockString);
    }

}
