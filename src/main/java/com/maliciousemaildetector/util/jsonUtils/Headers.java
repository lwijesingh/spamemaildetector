package com.maliciousemaildetector.util.jsonUtils;

//import org.apache.commons.codec.binary.Base64;

import java.util.HashMap;

public class Headers {

    public Headers() {
    }

    public static HashMap<String, String> getHeader() {
        HashMap<String, String> headers = new HashMap();
        headers.put("Content-Type", "application/json");
        headers.put("API-Key", "818a0a03-4766-4439-af74-644395c6db34");
        return headers;
    }

    public static HashMap<String, String> getVirusTotalHeader() {
        HashMap<String, String> headers = new HashMap();
        headers.put("x-apikey", "65c1f067cf5539caa7e9a1555d94b85c47b24026f45ac943a4da73332c696631");
        return headers;
    }
}
