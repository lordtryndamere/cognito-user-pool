package com.appsdeveloperblog.aws.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.appsdeveloperblog.aws.lambda.constants.Constants;
import com.appsdeveloperblog.aws.lambda.service.CognitoUserService;
import com.appsdeveloperblog.aws.lambda.utils.Utils;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

import java.util.HashMap;
import java.util.Map;

public class ResetPasswordHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private final CognitoUserService cognitoUserService;
    private final String appClientId;
    private final String appClientSecret;
    public ResetPasswordHandler(){
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
            String requestBody = input.getBody();
            logger.log("Original json body:" + requestBody);
            JsonObject forgotPasswordFlowDetails = JsonParser.parseString(requestBody).getAsJsonObject();
            String action = forgotPasswordFlowDetails.get("action").getAsString();
            String username = forgotPasswordFlowDetails.get("username").getAsString();
            if (action.equals("initiatePasswordReset")) {
               JsonObject initiatePasswordResult =  cognitoUserService.initiatePasswordReset(username,appClientId,appClientSecret);
               response.withBody(initiatePasswordResult.toString());
               response.withStatusCode(200);
            }else if (action.equals("resetPassword")) {
                String newPassword = forgotPasswordFlowDetails.get("newPassword").getAsString();
                String confirmationCode = forgotPasswordFlowDetails.get("confirmationCode").getAsString();
                JsonObject resetPasswordResult =
                        cognitoUserService.confirmPasswordReset(username,newPassword,confirmationCode,appClientId,appClientSecret);
                response.withBody(resetPasswordResult.toString());
                response.withStatusCode(200);
            }else{
                response.withStatusCode(400);
                response.withBody("Invalid action ");
            }

        }catch (JsonSyntaxException e) {
            response.setStatusCode(500);
            response.setBody("Internal Server Error : " + e.getMessage());
        }
        return response;
    }
}
