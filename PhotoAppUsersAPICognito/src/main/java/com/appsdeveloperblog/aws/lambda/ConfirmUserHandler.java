package com.appsdeveloperblog.aws.lambda;

import java.util.HashMap;
import java.util.Map;

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
import com.google.gson.JsonSyntaxException;

import software.amazon.awssdk.awscore.exception.AwsServiceException;

public class ConfirmUserHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final CognitoUserService cognitoUserService;
    private final String appClientId;
    private final String appClientSecret;

    public ConfirmUserHandler() {
        final String AWS_REGION = System.getenv(Constants.AWS_REGION);
        this.cognitoUserService = new CognitoUserService(AWS_REGION);
        this.appClientId = Utils.validateAndTrimClientId(Utils.decryptKey(Constants.MY_COGNITO_POOL_APP_CLIENT_ID));
        this.appClientSecret = Utils.decryptKey(Constants.MY_COGNITO_POOL_APP_CLIENT_SECRET).trim();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {
        Map<String, String> headers = new HashMap<>();
        APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent()
                .withHeaders(headers);
        LambdaLogger logger = context.getLogger();
        headers.put("Content-Type", "application/json");

        try {
            String bodyJsonString = input.getBody();
            JsonObject body = JsonParser.parseString(bodyJsonString).getAsJsonObject();
            String email = body.get("email").getAsString();
            String confirmationCode = body.get("confirmationCode").getAsString();
            JsonObject confirmUserResult = cognitoUserService.confirmUserSignup(appClientId, appClientSecret, email, confirmationCode);
            response.withStatusCode(200);
            response.withBody(new Gson().toJson(confirmUserResult, JsonObject.class));
        } catch (AwsServiceException ex) {
            String errorMessage = ex.awsErrorDetails().errorMessage();
            logger.log(errorMessage);
            response.withBody(errorMessage).withStatusCode(ex.awsErrorDetails().sdkHttpResponse().statusCode());
        } catch (JsonSyntaxException ex) {
            logger.log(ex.getMessage());
            response.withBody(ex.getMessage());
            response.withStatusCode(500);
        }

        return response;
    }
}
