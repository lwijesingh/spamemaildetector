package com.maliciousemaildetector.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class WelcomePageController {

    @GetMapping("/")
    public String index() {
        return "login";
    }
    @GetMapping("/scan")
    public String scan() {
        return "scan";
    }

}
