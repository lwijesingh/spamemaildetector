package com.maliciousemaildetector.common;

import com.jayway.restassured.RestAssured;
import com.jayway.restassured.builder.RequestSpecBuilder;
import com.jayway.restassured.config.EncoderConfig;
import com.jayway.restassured.response.Response;
import com.jayway.restassured.specification.RequestSpecification;
import org.json.JSONObject;

import java.util.Iterator;
import java.util.Map;


public class RestUtil {
    public static String API_HOST;
    public static String BASE_PATH;
    public static int PORT = 0;

    public RestUtil() {
    }

    public static Response send(Map<String, String> headers, String bodyString, String uri, String requestMethod) {
        return send(headers, bodyString, uri, requestMethod, (Map) null);
    }

    public static Response send(Map<String, String> headers, String bodyString, String uri, String requestMethod, Map<String, String> queryParameters) {
        RestAssured.baseURI = API_HOST;
        RestAssured.basePath = BASE_PATH;
        if (PORT != 0) {
            RestAssured.port = PORT;
        }

        System.out.println("\n\nHEADERS\n" + headers + "\n*********\n\n");
        System.out.println("\n\nREQUEST_URL\n" + RestAssured.baseURI + RestAssured.basePath + "/" + uri + "\n*********\n\n");
        RequestSpecification requestSpecification = getRequestSpec(headers, bodyString);
        System.out.println("\n\nREQUEST_BODY\n" + bodyString + "\n*********\n\n");
        RestAssured.useRelaxedHTTPSValidation();
        requestSpecification = RestAssured.given().spec(requestSpecification);
        String theUri = setQueryParameters(uri, queryParameters);
        Response response = execute(requestMethod, requestSpecification, theUri);
        System.out.println("\n\nRESPONSE\n" + response.getBody().asString() + "\n*********\n\n");
        System.out.println("\n\nRESPONSE_STATUS_CODE\n" + response.getStatusCode() + "\n*********\n\n");
        return response;
    }

    public static RequestSpecification getRequestSpec(Map<String, String> headers, String body) {
        RequestSpecBuilder reqSpecBuilder = new RequestSpecBuilder();
        if (headers != null) {
            reqSpecBuilder.addHeaders(headers);
        }

        if (body != null && body.length() > 0) {
            reqSpecBuilder.setBody(body);
        }

        return reqSpecBuilder.build();
    }

    public static String setQueryParameters(String url, Map<String, String> queryParameters) {
        if (queryParameters != null && !queryParameters.isEmpty()) {
            String newUrl = url.concat("?");

            String key;
            String value;
            for(Iterator var3 = queryParameters.entrySet().iterator(); var3.hasNext(); newUrl = newUrl.concat(key).concat("=").concat(value).concat("&")) {
                Map.Entry<String, String> entry = (Map.Entry)var3.next();
                key = (String)entry.getKey();
                value = (String)entry.getValue();
            }

            return newUrl.substring(0, newUrl.length() - 1);
        } else {
            return url;
        }
    }

    public static Response execute(String reqMethod, RequestSpecification requestSpec, String uri) {
        RequestSpecification requestSpecification = RestAssured.given(requestSpec).config(RestAssured.config().encoderConfig(EncoderConfig.encoderConfig().appendDefaultContentCharsetToContentTypeIfUndefined(false)));
        Response response = null;
        if ("GET".equalsIgnoreCase(reqMethod)) {
            response = (Response)requestSpecification.expect().when().get(uri, new Object[0]);
        }

        if ("POST".equalsIgnoreCase(reqMethod)) {
            response = (Response)requestSpecification.expect().when().post(uri, new Object[0]);
        }

        if ("PUT".equalsIgnoreCase(reqMethod)) {
            response = (Response)requestSpecification.expect().when().put(uri, new Object[0]);
        }

        if ("DELETE".equalsIgnoreCase(reqMethod)) {
            response = (Response)requestSpecification.expect().when().delete(uri, new Object[0]);
        }

        if ("PATCH".equalsIgnoreCase(reqMethod)) {
            response = (Response)requestSpecification.expect().when().patch(uri, new Object[0]);
        }

        return response != null ? response : null;
    }

    public static String getValue(Response response, String key) {
        return getValue(response.asString(), key);
    }

    public static String getValue(String response, String key) {
        String value = "";

        try {
            if (response.charAt(0) != '{' && response.charAt(response.length() - 1) != '}') {
                response = response.replace(response.substring(0, 1), "");
                response = response.replace(response.substring(response.length() - 1, response.length()), "");
            }

            JSONObject responseBody;
            try {
                responseBody = new JSONObject(response);
                value = responseBody.getString(key);
            } catch (Exception var17) {
                ;
            }

            try {
                responseBody = new JSONObject(response);
                value = String.valueOf(responseBody.getBoolean(key));
            } catch (Exception var16) {
                ;
            }

            try {
                responseBody = new JSONObject(response);
                value = String.valueOf(responseBody.getInt(key));
            } catch (Exception var15) {
                ;
            }

            try {
                responseBody = new JSONObject(response);
                value = String.valueOf(responseBody.getDouble(key));
            } catch (Exception var14) {
                ;
            }

            try {
                responseBody = new JSONObject(response);
                value = String.valueOf(responseBody.getJSONObject(key));
            } catch (Exception var13) {
                ;
            }

            try {
                responseBody = new JSONObject(response);
                value = String.valueOf(responseBody.getJSONArray(key));
            } catch (Exception var12) {
                ;
            }

            return value;
        } finally {
            ;
        }
    }

    public static int getResponseCode(Response response) {
        return response.getStatusCode();
    }

}

