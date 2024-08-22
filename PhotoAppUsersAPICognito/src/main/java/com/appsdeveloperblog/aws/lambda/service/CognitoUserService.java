package com.appsdeveloperblog.aws.lambda.service;

import com.google.gson.JsonObject;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

public class CognitoUserService {
    private final CognitoIdentityProviderClient cognitoIdentityProviderClient;


    public CognitoUserService(String region) {
        this.cognitoIdentityProviderClient = CognitoIdentityProviderClient.builder()
                .region(Region.of(region))
                .build();
    }

    public CognitoUserService(CognitoIdentityProviderClient cognitoIdentityProviderClient) {
        this.cognitoIdentityProviderClient = cognitoIdentityProviderClient;
    }

    public JsonObject createUser(JsonObject user, String appClientId, String appClientSecret) {
        JsonObject createUserResult = new JsonObject();
        List<AttributeType> attributeTypes = new ArrayList<>();
        String email = user.get("email").getAsString();
        String password = user.get("password").getAsString();
        String address = user.get("address").getAsString();
        String birthdate = user.get("birthdate").getAsString();
        String gender = user.get("gender").getAsString();
        String phone_number = user.get("phone_number").getAsString();
        String name = user.get("name").getAsString();
        String userId = UUID.randomUUID().toString();

        AttributeType emailAttribute = AttributeType.builder()
                .name("email")
                .value(email)
                .build();
        AttributeType addressAttribute = AttributeType.builder()
                .name("address")
                .value(address)
                .build();

        AttributeType birthdateAttribute = AttributeType.builder()
                .name("birthdate")
                .value(birthdate)
                .build();
        AttributeType genderAttribute = AttributeType.builder()
                .name("gender")
                .value(gender)
                .build();
        AttributeType phoneNumberAttribute = AttributeType.builder()
                .name("phone_number")
                .value(phone_number)
                .build();
        AttributeType nameAttribute = AttributeType.builder()
                .name("name")
                .value(name)
                .build();

        AttributeType attributeUserId = AttributeType.builder()
                .name("custom:userId")
                .value(userId)
                .build();

        attributeTypes.add(emailAttribute);
        attributeTypes.add(addressAttribute);
        attributeTypes.add(birthdateAttribute);
        attributeTypes.add(genderAttribute);
        attributeTypes.add(phoneNumberAttribute);
        attributeTypes.add(nameAttribute);
//        attributeTypes.add(attributeUserId);


        String generatedSecretHash = calculateSecretHash(appClientId, appClientSecret, email);



        SignUpRequest signUpRequest = SignUpRequest.builder()
                .username(email)
                .password(password)
                .userAttributes(attributeTypes)
                .clientId(appClientId)
                .secretHash(generatedSecretHash)
                .build();

        SignUpResponse signUpResponse = cognitoIdentityProviderClient.signUp(signUpRequest);
        createUserResult.addProperty("isSuccessful", signUpResponse.sdkHttpResponse().isSuccessful());
        createUserResult.addProperty("statusCode", signUpResponse.sdkHttpResponse().statusCode());
        createUserResult.addProperty("cognitoUserId", signUpResponse.userSub());
        createUserResult.addProperty("isConfirmed", signUpResponse.userConfirmed());
        return createUserResult;
    }
    public void userLogin(JsonObject user, String appClientId, String appClientSecret){

    }

    public JsonObject confirmUserSignup(String appClientId, String appClientSecret, String email, String confirmationCode) {
        String generatedSecretHash = calculateSecretHash(appClientId, appClientSecret, email);


       ConfirmSignUpRequest confirmSignUpRequest =  ConfirmSignUpRequest.builder()
                .secretHash(generatedSecretHash)
                .username(email)
                .confirmationCode(confirmationCode)
                .clientId(appClientId)
                .build();

       ConfirmSignUpResponse confirmSignUpResponse =  cognitoIdentityProviderClient.confirmSignUp(confirmSignUpRequest);
       JsonObject confirmUserResponse = new JsonObject();
       confirmUserResponse.addProperty("isSuccessful", confirmSignUpResponse.sdkHttpResponse().isSuccessful());
       confirmUserResponse.addProperty("statusCode", confirmSignUpResponse.sdkHttpResponse().statusCode());
       return confirmUserResponse;

    }

    public String calculateSecretHash(String userPoolClientId, String userPoolClientSecret, String userName) {
        final String HMAC_SHA256_ALGORITHM = "HmacSHA256";

        SecretKeySpec signingKey = new SecretKeySpec(
                userPoolClientSecret.getBytes(StandardCharsets.UTF_8),
                HMAC_SHA256_ALGORITHM);
        try {
            Mac mac = Mac.getInstance(HMAC_SHA256_ALGORITHM);
            mac.init(signingKey);
            mac.update(userName.getBytes(StandardCharsets.UTF_8));
            byte[] rawHmac = mac.doFinal(userPoolClientId.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(rawHmac);
        } catch (Exception e) {
            throw new RuntimeException("Error while calculating ");
        }
    }

}

