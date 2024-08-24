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

public class LoginUserHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {


    private final CognitoUserService cognitoUserService;
    private final String appClientId;
    private final String appClientSecret;

    public LoginUserHandler() {
        final String AWS_REGION = System.getenv(Constants.AWS_REGION);
        this.cognitoUserService = new CognitoUserService(AWS_REGION);
        this.appClientId =  Utils.validateAndTrimClientId(Utils.decryptKey(Constants.MY_COGNITO_POOL_APP_CLIENT_ID));
        this.appClientSecret = Utils.decryptKey(Constants.MY_COGNITO_POOL_APP_CLIENT_SECRET).trim();
    }


    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {
        Map<String, String> headers = new HashMap<>();
        APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent()
                .withHeaders(headers);
        LambdaLogger logger = context.getLogger();
        headers.put("Content-Type", "application/json");

        //Code Here

        try {
            String requestBody = input.getBody();
            logger.log("Original json body:" + requestBody);
            JsonObject userDetails = JsonParser.parseString(requestBody).getAsJsonObject();
                   try {
                JsonObject loginUserResult = cognitoUserService.userLogin(userDetails, appClientId, appClientSecret.trim());
                response.withStatusCode(200);
                response.withBody(new Gson().toJson(loginUserResult, JsonObject.class));
            } catch (AwsServiceException ex) {
                logger.log(ex.awsErrorDetails().errorMessage());
                response.withStatusCode(500);
                response.withBody(ex.awsErrorDetails().errorMessage());
            }

            
        } catch (JsonSyntaxException e) {
            response.setStatusCode(500);
            response.setBody("Internal Server Error : " + e.getMessage());
        }


        return  response;
    }
}
