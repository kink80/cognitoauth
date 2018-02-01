# AWS Cognito User pool authentication helper

This library aims to fill the gap for pure Java based apps that want to interact with User Pools in AWS  Cognito. The goal is to support user login into federated identity pool that
would allow this user to be provided with AWS temporary credentials. These credentials can be used later on in order to consume other AWS resources.


### Prerequisities

- A user pool exists in AWS Cognito service
- The user pools has an client application registered with it
    - The client app does not need to have app secret associated with it
- An identity pool exists in AWS Cognito Federated identities
    - Authentication provider within this identity pool points to
     the user pool id and app client id defined in the previous step
- A user is registered into the user pool     
- IAM security role exists and users from the given pool are permitted to use AWS resources, the policy itself might look like this
  if you're accessing S3 resources
~~~~
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "mobileanalytics:PutEvents",
                "cognito-sync:*",
                "cognito-identity:*"
            ],
            "Resource": [
                "*"
            ]
        },
        {
            "Action": [
                "s3:ListBucket"
            ],
            "Effect": "Allow",
            "Resource": [
                "arn:aws:s3:::your-bucket-name"
            ],
            "Condition": {
                "StringLike": {
                    "s3:prefix": [
                        "${cognito-identity.amazonaws.com:sub}/*"
                    ]
                }
            }
        },
        {
            "Action": [
                "s3:GetObject",
                "s3:PutObject"
            ],
            "Effect": "Allow",
            "Resource": [
                "arn:aws:s3:::your-bucket-name/${cognito-identity.amazonaws.com:sub}/*"
            ]
        }
    ]
}
~~~~
- IAM trust relationship between the role and identity pool exists, here's a sample policy
~~~~
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "cognito-identity.amazonaws.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "cognito-identity.amazonaws.com:aud": "identity pool id"
        },
        "ForAnyValue:StringLike": {
          "cognito-identity.amazonaws.com:amr": "authenticated"
        }
      }
    }
  ]
}
~~~~
----
### Usage

Note down following properties from your AWS account

- user pool id
- username
- password
- region
- client application id
- account id
- identity pool id
- endpoint of your idenity pool

----

**Initialize cryptographic routines first and perform initial setup**
~~~~
AWSCryptoSettings cryptoParams = new AWSCryptoSettings();
AWSCognitoSession clientSession = new AWSCognitoSession(cryptoParams, "username", "password", "user pool id");
~~~~

**Initiate authentication request**
~~~~
WSCognitoIdentityProviderClient identityProviderClient = new AWSCognitoIdentityProviderClient(new AnonymousAWSCredentials());
identityProviderClient.setRegion("region");

InitiateAuthRequest authRequest = new InitiateAuthRequest()
    .withAuthFlow(AuthFlowType.USER_SRP_AUTH)
    .withClientId("client application id")
    .withAuthParameters(clientSession.step1());
~~~~

**Respond to authentication challenge**
~~~~
InitiateAuthResult authResult = identityProviderClient.initiateAuth(authRequest);
Map<String, String> params = authResult.getChallengeParameters();
Map<String, String> srpAuthResponses = clientSession.step2(params);

RespondToAuthChallengeRequest respondToAuthChallengeRequest = new RespondToAuthChallengeRequest()
    .withChallengeName(authResult.getChallengeName())
    .withClientId("client application id")
    .withChallengeResponses(srpAuthResponses);
RespondToAuthChallengeResult respondToAuthChallengeResult = identityProviderClient.respondToAuthChallenge(respondToAuthChallengeRequest);
AuthenticationResultType authenticationResultType = respondToAuthChallengeResult.getAuthenticationResult();
~~~~

**Your user pool can have devices enabled, in that case you need them using following routine**
~~~~
if(authenticationResultType.getNewDeviceMetadata() != null) {
  NewDeviceMetadataType deviceMetadata = authenticationResultType.getNewDeviceMetadata();

  final AWSDeviceContext deviceContext = clientSession.getDeviceContext(deviceMetadata.getDeviceKey(),
                                      deviceMetadata.getDeviceGroupKey());

  final DeviceSecretVerifierConfigType deviceConfig = new DeviceSecretVerifierConfigType();
  deviceConfig.setPasswordVerifier(deviceContext.getPasswordVerifier());
  deviceConfig.setSalt(deviceContext.getSalt());

  ConfirmDeviceRequest confirmDeviceRequest = new ConfirmDeviceRequest();
  confirmDeviceRequest.setAccessToken(authenticationResultType.getAccessToken());
  confirmDeviceRequest.setDeviceKey(authenticationResultType.getNewDeviceMetadata().getDeviceKey());
  confirmDeviceRequest.setDeviceName("someDeviceName");
  confirmDeviceRequest.setDeviceSecretVerifierConfig(deviceConfig);
  ConfirmDeviceResult confirmDeviceResult = identityProviderClient.confirmDevice(confirmDeviceRequest);
  confirmDeviceResult.getUserConfirmationNecessary();
}
~~~~

You should be successfully authenticated at this stage, now let's obtain our AWS credentials through cognito.

**Initialize Cognito identity client**
~~~~
AmazonCognitoIdentityClient cognitoIdentityClient = new AmazonCognitoIdentityClient(new AnonymousAWSCredentials());
cognitoIdentityClient.setRegion("region");
~~~~

**Obtain an ID from the Cogntito user pool**
~~~~
Map<String, String> loginsMap = new HashMap<String, String>();
// e.g. cognito-idp.eu-central-1.amazonaws.com/user_pool_id
loginsMap.put("endpoint of your idenity pool/user pool id", authenticationResultType.getIdToken());

GetIdRequest getIdRequest = new GetIdRequest().withAccountId("account id")
    .withIdentityPoolId("identity pool id)
    .withLogins(loginsMap);

GetIdResult getIdResult = cognitoIdentityClient.getId(getIdRequest);
~~~~

**And finally, get credentials**
~~~~
GetCredentialsForIdentityRequest credentialsForIdentityRequest = new GetCredentialsForIdentityRequest()
            .withIdentityId(getIdResult.getIdentityId())
            .withLogins(loginsMap);

GetCredentialsForIdentityResult credentialsForIdentityResult = cognitoIdentityClient.getCredentialsForIdentity(credentialsForIdentityRequest);
credentialsForIdentityResult.getCredentials();

AWSSessionCredentials sessionCredentials = new BasicSessionCredentials(
    credentialsForIdentityResult.getCredentials().getAccessKeyId(),
    credentialsForIdentityResult.getCredentials().getSecretKey(),
    credentialsForIdentityResult.getCredentials().getSessionToken());
~~~~

### Maven

This project is available in Maven:

groupId: com.github.kink80

artifactId: cognitoauth

version: 1.+
