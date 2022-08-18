package com.maliciousemaildetector.util.jsonUtils;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.maliciousemaildetector.util.urlscan.UrlScan;

import java.io.FileNotFoundException;
import java.io.FileReader;

public class JsonReaderUtil {
    private static final String DIR = "user.dir";
    private static final String USER_DIR = System.getProperty(DIR);
    private static final Gson gson = new Gson();
    public static UrlScan[] getTokenRequest() throws FileNotFoundException {
        JsonElement root = new JsonParser().parse(new FileReader(USER_DIR + "/src/main/resources/data/UrlScanTokenRequest.json"));
        return gson.fromJson(root, UrlScan[].class);
    }

    public static <T> String objectToJson(T objectToJson) {
        return gson.toJson(objectToJson);
    }

}
