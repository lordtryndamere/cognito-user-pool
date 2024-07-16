package com.appsdeveloperblog.aws.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.appsdeveloperblog.aws.lambda.constants.Constants;
import com.appsdeveloperblog.aws.lambda.service.CognitoUserService;
import com.appsdeveloperblog.aws.lambda.utils.Utils;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import software.amazon.awssdk.awscore.exception.AwsServiceException;

import java.util.HashMap;
import java.util.Map;

/**
 * Handler for requests to Lambda function.
 */
public class CreateUserHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private final CognitoUserService cognitoUserService;
    private final String appClientId;
    private final String appClientSecret;

    public CreateUserHandler() {
        String AWS_REGION = System.getenv(Constants.AWS_REGION);
        this.cognitoUserService = new CognitoUserService(AWS_REGION);
        this.appClientId =  Utils.validateAndTrimClientId(Utils.decryptKey(Constants.MY_COGNITO_POOL_APP_CLIENT_ID));
        this.appClientSecret = Utils.decryptKey(Constants.MY_COGNITO_POOL_APP_CLIENT_SECRET);
    }

    public APIGatewayProxyResponseEvent handleRequest(final APIGatewayProxyRequestEvent input, final Context context) {
        Map<String, String> headers = new HashMap<>();
        LambdaLogger logger = context.getLogger();
        headers.put("Content-Type", "application/json");
        APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent()
                .withHeaders(headers);
        try {
            String requestBody = input.getBody();
            logger.log("Original json body:" + requestBody);

            JsonObject userDetails = JsonParser.parseString(requestBody).getAsJsonObject();

            try {
                JsonObject createUserResult = cognitoUserService.createUser(userDetails, appClientId, appClientSecret.trim());
                response.withStatusCode(200);
                response.withBody(new Gson().toJson(createUserResult, JsonObject.class));
            } catch (AwsServiceException ex) {
                logger.log(ex.awsErrorDetails().errorMessage());
                response.withStatusCode(500);
                response.withBody(ex.awsErrorDetails().errorMessage());
            }

        } catch (Exception e) {
            response.setStatusCode(500);
            response.setBody("Internal Server Error : " + e.getMessage());
        }
        return response;

    }

}
