package com.appsdeveloperblog.aws.lambda.utils;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.util.Base64;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class Utils {

    public static String decryptKey(String name) {
        System.out.println("Decrypting key");
        byte[] encryptedKey = Base64.decode(System.getenv(name));
        AWSKMS client = AWSKMSClientBuilder.defaultClient();
        DecryptRequest request = new DecryptRequest()
                .withCiphertextBlob(ByteBuffer.wrap(encryptedKey));
        ByteBuffer plainTextKey = client.decrypt(request).getPlaintext();
        return new String(plainTextKey.array(), StandardCharsets.UTF_8);
    }

    public static  String validateAndTrimClientId(String clientId) {
        String trimmedClientId = clientId.trim();
        if (!trimmedClientId.matches("[\\w+]+")) {
            throw new IllegalArgumentException("Invalid clientId format.");
        }
        return trimmedClientId;
    }

}
