package com.maliciousemaildetector.controller;

import com.maliciousemaildetector.util.WekaPredictionUtil;
import com.maliciousemaildetector.dto.EmailData;
import com.maliciousemaildetector.util.urlscan.UrlScan;
import com.maliciousemaildetector.util.jsonUtils.JsonReaderUtil;
import com.maliciousemaildetector.common.JsonCommonUtil;
import com.maliciousemaildetector.util.jsonUtils.RequestUtil;
import com.maliciousemaildetector.service.EmailLoginService;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;
import javax.mail.*;
import javax.mail.internet.MimeMultipart;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Logger;

@RestController
public class FileUploadRestController {
    private static final Logger LOGGER = Logger.getLogger(FileUploadRestController.class.getName());
    ArrayList<Message> messages = new ArrayList<>();
    private static EmailLoginService emailUtils;
    private static UrlScan[] urlScans;
    Message[] messages2;
    public static final String COMPLETE_EVENT_NAME = "COMPLETE";
    public static final String COMPLETE_EVENT_DATA = "{\"name\": \"COMPLETED_STREAM\"}";

    @RequestMapping(value = "/api/login")
    @GetMapping
    public void getLoginInformation(@RequestBody String data) throws JSONException, IOException, MessagingException {
        JSONObject jsonObj = new JSONObject(data);
        String accountType = "GMail";
        String userName = jsonObj.getString("username");
        String password = jsonObj.getString("password");
        EmailData emailData[] = JsonCommonUtil.getJSONArray(EmailData[].class);
        String emailType = accountType;
        switch (emailType) {
            case "GMail":
                emailData[0].setEmailID(userName + "@gmail.com");
                emailData[0].setToken(password);
                emailData[0].setServer("imap.googlemail.com");
                break;
            case "Yahoo":
                emailData[1].setEmailID(userName + "@yahoo.com");
                emailData[1].setToken(password);
                emailData[1].setServer("imap.mail.yahoo.com");
                break;
            case "Office365":
                emailData[1].setEmailID(userName + "@outlook.com");
                emailData[1].setToken(password);
                emailData[1].setServer("outlook.office365.com");
                break;
        }

        urlScans = JsonReaderUtil.getTokenRequest();

        try {
            emailUtils = new EmailLoginService(emailData[0].getEmailID(), emailData[0].getToken(), emailData[0].getServer(), EmailLoginService.EmailFolder.INBOX);
        } catch (AuthenticationFailedException e) {
            throw e;

        }
        Message[] messages = emailUtils.getAllEmails();
        HashMap<Message, String> sessionMessages = new HashMap<>();
        for (Message message : messages) {
            MimeMultipart mimeMultipart = (MimeMultipart) message.getContent();
            String result = emailUtils.getTextFromMimeMultipart(mimeMultipart);
            sessionMessages.put(message, result);
            message.setFlag(Flags.Flag.SEEN, false);
        }

        int messageSize = emailUtils.getAllEmails().length;
        messages2 = new Message[messageSize];
        String[] msgBody = new String[messageSize];
        int i = 0;
        for (Map.Entry<Message, String> email : sessionMessages.entrySet()) {
            messages2[i] = email.getKey();
            msgBody[i] = email.getValue();
            i++;
        }
    }

    @RequestMapping("/api/logout")
    @GetMapping
    public void logout() throws Exception {
        emailUtils.logOut();
    }

    @GetMapping("/api/scanEmailsByUrl")
    @CrossOrigin
    public SseEmitter scanEmailsByUrl() throws Exception {
        final ExecutorService executor = Executors.newFixedThreadPool(1);
        SseEmitter sseEmitter = new SseEmitter(Long.MAX_VALUE);
        sseEmitter.onCompletion(() -> LOGGER.info("SseEmitter is completed"));
        sseEmitter.onTimeout(() -> LOGGER.info("SseEmitter is timed out"));
        sseEmitter.onError((ex) -> LOGGER.warning("warning"));
        executor.execute(() -> { // /
            Message[] allUnreadEmail = new Message[0];
            try {
                allUnreadEmail = emailUtils.getAllEmails();
            } catch (MessagingException e) {
                e.printStackTrace();
            }
            HashMap<Message, ArrayList<String>> messagesContainingUrls = null;
            try {
                messagesContainingUrls = emailUtils.getMessageAndURl(allUnreadEmail);
            } catch (Exception e) {
                e.printStackTrace();
            }
            int l = allUnreadEmail.length;
            int j = 0;
            int k = messagesContainingUrls.size();
            //  for (Map.Entry<Message, ArrayList<String>> entry : messagesContainingUrls.entrySet()) {
            for (Map.Entry<Message, ArrayList<String>> entry : messagesContainingUrls.entrySet()) {
                try {
                    k--;
                    for (int i = 0; i < entry.getValue().size(); i++) {
                        //sseEmitter.send(LocalDateTime.now().format(DateTimeFormatter.ofPattern("dd-MM-yyyy hh:mm:ss")));
                        String url = entry.getValue().get(i).replaceAll("https://", "").replaceAll("http://", "");
                        urlScans[0].url = url;
                       // Boolean urlScanStatus = RequestUtil.getUrlScanMaliciousStatus(urlScans[0]);
                        Boolean virusTotalStatus = RequestUtil.getVirusTotalMaliciousStatus(url);
                        if (virusTotalStatus || virusTotalStatus) {
                            messages.add(entry.getKey());
                            j++;
                            break;
                        }
                    }
                    sseEmitter.send((messagesContainingUrls.size() - k) + "_" + messagesContainingUrls.size());
                    // sseEmitter.send(allUnreadEmail.length - l + "_" + allUnreadEmail.length);
                    ;
                } catch (Exception e) {
                    e.printStackTrace();
                    sseEmitter.completeWithError(e);
                }
            }
            try {
                sseEmitter.send(SseEmitter.event().
                        id(String.valueOf(System.currentTimeMillis()))
                        .name(COMPLETE_EVENT_NAME)
                        .data(COMPLETE_EVENT_DATA));
                sseEmitter.complete();
            } catch (IOException e) {
                e.printStackTrace();
            }

        });
        return sseEmitter;
    }

    @GetMapping("/api/scanEmailsByML")
    @CrossOrigin
    public SseEmitter scanEmailsByML() throws Exception {
        //ArrayList<Message> messages = new ArrayList<>();
        final ExecutorService executor = Executors.newFixedThreadPool(1);
        SseEmitter sseEmitter = new SseEmitter(Long.MAX_VALUE);
        sseEmitter.onCompletion(() -> LOGGER.info("SseEmitter is completed"));
        sseEmitter.onTimeout(() -> LOGGER.info("SseEmitter is timed out"));
        sseEmitter.onError((ex) -> LOGGER.warning("warning"));
        executor.execute(() -> {
            try {
                HashMap<Message, String> messageContent = emailUtils.getMessageContent();
                int j = 0;
                for (Map.Entry<Message, String> entry : messageContent.entrySet()) {
                    j++;
                    double isSpam = WekaPredictionUtil.getPrediction(entry.getValue());
                    if ((int) isSpam == 1) {
                        messages.add(entry.getKey());
                        //break;
                    }
                    sseEmitter.send((j) + "_" + messageContent.size());
                }

            } catch (Exception e) {
                e.printStackTrace();
                sseEmitter.completeWithError(e);
            }
            try {
                sseEmitter.send(SseEmitter.event().
                        id(String.valueOf(System.currentTimeMillis()))
                        .name(COMPLETE_EVENT_NAME)
                        .data(COMPLETE_EVENT_DATA));
                sseEmitter.complete();
            } catch (IOException e) {
                e.printStackTrace();
            }

        });
        return sseEmitter;
    }

    @GetMapping("/api/moveEmails")
    @CrossOrigin
    public SseEmitter moveEmails() throws Exception {
        final ExecutorService executor = Executors.newFixedThreadPool(1);
        SseEmitter sseEmitterMoveEmails = new SseEmitter(Long.MAX_VALUE);
        sseEmitterMoveEmails.onCompletion(() -> LOGGER.info("Move email SseEmitter is completed"));
        sseEmitterMoveEmails.onTimeout(() -> LOGGER.info("Move email SseEmitter is timed out"));
        sseEmitterMoveEmails.onError((ex) -> LOGGER.warning("Move email warning"));
        Message[] messages2;
        messages2 = messages.toArray(new Message[0]);
        Folder folder = emailUtils.getFolderByName("SPAM2");
        if (!folder.exists())
            folder.create(Folder.HOLDS_MESSAGES);

        if (messages2.length != 0) {
            emailUtils.getFolder().copyMessages(messages2, folder);
            emailUtils.getFolder().setFlags(messages2, new Flags(Flags.Flag.DELETED), true);
            executor.execute(() -> {
                try {
                    for (int i = 0; i < messages2.length; i++) {
                        try {
                            if (!messages2[i].isSet(Flags.Flag.DELETED)) {
                                LOGGER.info("Message # " + messages2[i] + " not deleted");
                            } else {
                                sseEmitterMoveEmails.send(i + "_" + messages2.length);
                            }
                        } catch (MessagingException | IOException e) {
                            e.printStackTrace();
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    sseEmitterMoveEmails.completeWithError(e);
                }
                try {
                    sseEmitterMoveEmails.send(SseEmitter.event().
                            id(String.valueOf(System.currentTimeMillis()))
                            .name(COMPLETE_EVENT_NAME)
                            .data(COMPLETE_EVENT_DATA));
                    sseEmitterMoveEmails.complete();
                } catch (IOException e) {
                    e.printStackTrace();
                }

            });
        } else {
            sseEmitterMoveEmails.send("0");
            sseEmitterMoveEmails.complete();
        }
        return sseEmitterMoveEmails;
    }

    private void sleep(int seconds, SseEmitter sseEmitter) {
        try {
            Thread.sleep(seconds * 1000);
        } catch (InterruptedException e) {
            e.printStackTrace();
            sseEmitter.completeWithError(e);
        }
    }
}
