package com.maliciousemaildetector.service;

import javax.mail.*;
import javax.mail.internet.MimeMultipart;
import javax.mail.search.FlagTerm;
import java.io.IOException;
import java.util.*;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utility for interacting with an Email application
 */

public class EmailLoginService {
    private final Logger logger = Logger.getLogger(EmailLoginService.class.getName());

    private Folder folder;
    private Session emailSession;
    private Store store;

    public enum EmailFolder {
        INBOX("INBOX"),
        SPAM2("SPAM2"),
        SPAM("SPAM");

        private String text;

        private EmailFolder(String text) {
            this.text = text;
        }

        public String getText() {
            return text;
        }
    }

    public void logOut() throws MessagingException {
        folder.close();
        store.close();
    }

    public EmailLoginService(String username, String password, String server, EmailFolder emailFolder) throws MessagingException {
        Properties properties = new Properties();

        properties.put("mail.imap.host", server);
        properties.put("mail.imap.port", "993");
        properties.put("mail.imap.starttls.enable", "true");
        properties.put("mail.imap.ssl.trust", server);

        emailSession = Session.getDefaultInstance(properties);
        store = emailSession.getStore("imaps");
        store.connect(server, username, password);

        folder = store.getFolder(emailFolder.getText());
        folder.open(Folder.READ_WRITE);
    }

    public Folder getFolderByName(String folderName) throws MessagingException {
        return this.folder.getFolder(folderName);
    }

    public Folder getFolder() throws MessagingException {
        return this.folder;
    }

    public HashMap<Message, String> getMessageContent() throws Exception {
        HashSet<String> links = new HashSet<String>();
        ArrayList<String> bodyContent2 = new ArrayList<>();
        HashMap<Message, String> bodyContent = new HashMap<Message, String>();
        Message[] messages;
        HashMap<Message, ArrayList<String>> maliciousMessages = new HashMap<Message, ArrayList<String>>();
        BodyPart bp;
        messages = folder.search(
                new FlagTerm(new Flags(Flags.Flag.SEEN), false));
        // Sort messages from recent to oldest
        Arrays.sort(messages, (m1, m2) -> {
            try {
                return m2.getSentDate().compareTo(m1.getSentDate());
            } catch (MessagingException e) {
                throw new RuntimeException(e);
            }
        });

        for (Message message : messages) {
            HashSet<String> links3 = new HashSet<>();
            ArrayList<String> links4 = new ArrayList<>();
            Object obj = message.getContent();
            Multipart mp = (Multipart) obj;
            bp = (mp.getBodyPart(0));
            bodyContent.put(message, bp.getContent().toString());
            message.setFlag(Flags.Flag.SEEN, false);
        }

        return bodyContent;
    }

    public Message[] getAllEmails() throws MessagingException {
        Message[] messages;
        messages = folder.search(new FlagTerm(new Flags(Flags.Flag.SEEN), false));
        Arrays.sort(messages, (m1, m2) -> {
            try {
                return m2.getSentDate().compareTo(m1.getSentDate());
            } catch (MessagingException e) {
                throw new RuntimeException(e);
            }
        });
        return messages;
    }

    public HashMap<Message, ArrayList<String>> getMessageAndURl(Message[] messages) throws Exception {
        HashSet<String> links = new HashSet<String>();
        HashMap<Message, ArrayList<String>> maliciousMessages = new HashMap<Message, ArrayList<String>>();
        BodyPart bp;
        for (Message message : messages) {
            HashSet<String> links3 = new HashSet<>();
            ArrayList<String> links4 = new ArrayList<>();
            Object obj = message.getContent();
            Multipart mp = (Multipart) obj;
            bp = (mp.getBodyPart(0));

            MimeMultipart mimeMultipart = (MimeMultipart) message.getContent();
            String result = getTextFromMimeMultipart(mimeMultipart);

            // System.out.println(msgContent);
            //String pattern = "((?:https?|ftp)://)(?:\\S+(?::\\S*)?@)?(?:(?!(?:10|127)(?:\\.\\d{1,3}){3})(?!(?:169\\.254|192\\.168)(?:\\.\\d{1,3}){2})(?!172\\.(?:1[6-9]|2\\d|3[0-1])(?:\\.\\d{1,3}){2})(?:[1-9]\\d?|1\\d\\d|2[01]\\d|22[0-3])(?:\\.(?:1?\\d{1,2}|2[0-4]\\d|25[0-5])){2}(?:\\.(?:[1-9]\\d?|1\\d\\d|2[0-4]\\d|25[0-4]))|(?:(?:[a-z\\u00a1-\\uffff0-9]-*)*[a-z\\u00a1-\\uffff0-9]+)(?:\\.(?:[a-z\\u00a1-\\uffff0-9]-*)*[a-z\\u00a1-\\uffff0-9]+)*(?:\\.(?:[a-z\\u00a1-\\uffff]{2,}))\\.?)(?::\\d{2,5})?(?:[/?#]\\S*)?$";
            String pattern = "((?:(http|https|Http|Https|rtsp|Rtsp):\\/\\/(?:(?:[a-zA-Z0-9\\$\\-\\_\\.\\+\\!\\*\\'\\(\\)"
                    + "\\,\\;\\?\\&\\=]|(?:\\%[a-fA-F0-9]{2})){1,64}(?:\\:(?:[a-zA-Z0-9\\$\\-\\_"
                    + "\\.\\+\\!\\*\\'\\(\\)\\,\\;\\?\\&\\=]|(?:\\%[a-fA-F0-9]{2})){1,25})?\\@)?)?"
                    + "((?:(?:[a-zA-Z0-9][a-zA-Z0-9\\-]{0,64}\\.)+"   // named host
                    + "(?:"   // plus top level domain
                    + "(?:aero|arpa|asia|a[cdefgilmnoqrstuwxz])"
                    + "|(?:biz|b[abdefghijmnorstvwyz])"
                    + "|(?:cat|com|coop|c[acdfghiklmnoruvxyz])"
                    + "|d[ejkmoz]"
                    + "|(?:edu|e[cegrstu])"
                    + "|f[ijkmor]"
                    + "|(?:gov|g[abdefghilmnpqrstuwy])"
                    + "|h[kmnrtu]"
                    + "|(?:info|int|i[delmnoqrst])"
                    + "|(?:jobs|j[emop])"
                    + "|k[eghimnrwyz]"
                    + "|l[abcikrstuvy]"
                    + "|(?:mil|mobi|museum|m[acdghklmnopqrstuvwxyz])"
                    + "|(?:name|net|n[acefgilopruz])"
                    + "|(?:org|om)"
                    + "|(?:pro|p[aefghklmnrstwy])"
                    + "|qa"
                    + "|r[eouw]"
                    + "|s[abcdeghijklmnortuvyz]"
                    + "|(?:tel|travel|t[cdfghjklmnoprtvwz])"
                    + "|u[agkmsyz]"
                    + "|v[aceginu]"
                    + "|w[fs]"
                    + "|y[etu]"
                    + "|z[amw]))"
                    + "|(?:(?:25[0-5]|2[0-4]" // or ip address
                    + "[0-9]|[0-1][0-9]{2}|[1-9][0-9]|[1-9])\\.(?:25[0-5]|2[0-4][0-9]"
                    + "|[0-1][0-9]{2}|[1-9][0-9]|[1-9]|0)\\.(?:25[0-5]|2[0-4][0-9]|[0-1]"
                    + "[0-9]{2}|[1-9][0-9]|[1-9]|0)\\.(?:25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}"
                    + "|[1-9][0-9]|[0-9])))"
                    + "(?:\\:\\d{1,5})?)" // plus option port number
                    + "(\\/(?:(?:[a-zA-Z0-9\\;\\/\\?\\:\\@\\&\\=\\#\\~"  // plus option query params
                    + "\\-\\.\\+\\!\\*\\'\\(\\)\\,\\_])|(?:\\%[a-fA-F0-9]{2}))*)?"
                    + "(?:\\b|$)";
            Pattern linkPattern = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
            Matcher pageMatcher = linkPattern.matcher(result);
            while (pageMatcher.find()) {
                links.add(pageMatcher.group(1).replaceAll("https://", "").replaceAll("http://", ""));
                // links2.add(pageMatcher.group(1));
            }
            int i = 0;
            if (links.size() == 0) {
                message.setFlag(Flags.Flag.SEEN, false);
                break;
            } else {
                for (String temp : links) {
                    links3.add(temp);
                    links4 = new ArrayList<>(links3);
                    maliciousMessages.put(message, links4);
                    i++;
                }
                links.clear();
            }
            message.setFlag(Flags.Flag.SEEN, false);
        }
        return maliciousMessages;
    }

    public String getTextFromMimeMultipart(
            MimeMultipart mimeMultipart) throws MessagingException, IOException {
        String result = "";
        int count = mimeMultipart.getCount();
        for (int i = 0; i < count; i++) {
            BodyPart bodyPart = mimeMultipart.getBodyPart(i);
            if (bodyPart.isMimeType("text/plain")) {
                result = result + "\n" + bodyPart.getContent();
                break; // without break same text appears twice in my tests
            } else if (bodyPart.getContent() instanceof MimeMultipart) {
                result = result + getTextFromMimeMultipart((MimeMultipart) bodyPart.getContent());
            }
        }
        return result;
    }
}
