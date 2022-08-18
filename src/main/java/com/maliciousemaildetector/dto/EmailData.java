package com.maliciousemaildetector.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class EmailData {
        private String emailID;
        private String token;
        private String socketFactoryPort;
        private String emailClass;
        private String auth;
        private String smtpPort;
        private String protocol;
        private String server;

}
