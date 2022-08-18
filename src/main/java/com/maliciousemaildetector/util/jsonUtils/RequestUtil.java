package com.maliciousemaildetector.util.jsonUtils;


import com.maliciousemaildetector.common.RestUtil;
import com.jayway.restassured.path.json.JsonPath;
import com.jayway.restassured.response.Response;

public class RequestUtil {
    private static String uuid;

    RequestUtil() {

    }

    public static <T> String getURLScanAccessToken(T object) {
        RestUtil.API_HOST = "https://urlscan.io";
        RestUtil.BASE_PATH = "/api/v1/scan";
        Response response = RestUtil.send(Headers.getHeader(), JsonReaderUtil.objectToJson(object), "", "POST");

        return RestUtil.getValue(response, "uuid");
    }

    public static <T> Response getURLScanAccessResponse(T object) {
        RestUtil.API_HOST = "https://urlscan.io";
        RestUtil.BASE_PATH = "/api/v1/scan";
        Response response = RestUtil.send(Headers.getHeader(), JsonReaderUtil.objectToJson(object), "", "POST");

        return response;
    }

    public static Response getURLScanReport(String uri) {
        RestUtil.API_HOST = "https://urlscan.io";
        RestUtil.BASE_PATH = "/api/v1/result";
        Response response = RestUtil.send(null, "", uri, "GET");

        return response;
    }

    public static Response getVirusTotalReport(String url) {
        RestUtil.API_HOST = "https://www.virustotal.com";
        RestUtil.BASE_PATH = "/api/v3/domains";
        Response response = RestUtil.send(Headers.getVirusTotalHeader(), "", url, "GET");

        return response;
    }

    public static boolean getUrlScanMaliciousStatus(Object object) throws Exception {
        Boolean status;
        Response response002 = getURLScanAccessResponse(object);
        if (RestUtil.getValue(response002, "message").contains("Scan prevented")) {
            status = false;
        } else {
            uuid = getURLScanAccessToken(object);
            Thread.sleep(60000);
            Response response001 = RequestUtil.getURLScanReport(uuid);
            if (RestUtil.getValue(response002, "message").contains("Not Found")) {
                status = false;
            } else {
                JsonPath jsonPathEvaluator = response001.jsonPath();
                status = jsonPathEvaluator.getBoolean("verdicts.overall.malicious");
            }
        }
        return status;
    }

    public static boolean getVirusTotalMaliciousStatus(String url) throws Exception {
        Boolean status = false;
        Response response002 = RequestUtil.getVirusTotalReport(url);
        JsonPath jsonPathEvaluator02 = response002.jsonPath();
        int halmlessTotal = jsonPathEvaluator02.getInt("data.attributes.last_analysis_stats.harmless");
        int maliciousTotal = jsonPathEvaluator02.getInt("data.attributes.last_analysis_stats.malicious");
        int suspiciousTotal = jsonPathEvaluator02.getInt("data.attributes.last_analysis_stats.suspicious");
        int timeoutTotal = jsonPathEvaluator02.getInt("data.attributes.last_analysis_stats.timeout");
        int undetectedTotal = jsonPathEvaluator02.getInt("data.attributes.last_analysis_stats.undetected");
        if (maliciousTotal > 0 | suspiciousTotal > 0) {
            status = true;
        }
        return status;
    }

}
