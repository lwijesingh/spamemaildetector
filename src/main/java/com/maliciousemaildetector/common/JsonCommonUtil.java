package com.maliciousemaildetector.common;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.maliciousemaildetector.common.LoggerUtil;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Optional;
import java.util.logging.Level;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class JsonCommonUtil {
    private static final java.util.logging.Logger LOGGER_LOG = java.util.logging.Logger.getLogger("JsonReader");
    private static final Gson GSON = new Gson();
    private static List<String> result = null;

    static {
        try (Stream<Path> walk = Files.walk(Paths.get(System.getProperty("user.dir")+"/src/main/resources/data"))) {

            result = walk.filter(Files::isRegularFile)
                    .map(x -> x.toString()).collect(Collectors.toList());

        } catch (IOException e) {
            LOGGER_LOG.log(Level.WARNING, e.getMessage());
        }

    }

    private static <T> String loadFile(Class<T> tClass) {
        String[] classNameArr = tClass.getName().split("\\.");
        String className = classNameArr[classNameArr.length - 1].replace(";","").trim();
        String jsonFileName = className + ".json";
        String fileLoadPath ="";
        Optional<String > optional =result.stream().filter(x -> x.toLowerCase().endsWith(jsonFileName.toLowerCase())).findFirst();
        if(optional.isPresent()){
            fileLoadPath=optional.get();
        }
        return fileLoadPath;
    }


    public static <T> T[] getJSONArray(Class<T[]> tClass) {
        JsonParser jsonParser = new JsonParser();
        JsonElement element = null;
        try {
            element = jsonParser.parse(new FileReader(loadFile(tClass)));
        } catch (FileNotFoundException e) {
            LoggerUtil.logINFO(e.toString());
        }
        return GSON.fromJson(element, tClass);
    }
/*
    public static String getTestDataAsString(String filePath) {
        String content = null;
        File file = new File(filePath);
        FileReader reader = null;
        try {
            reader = new FileReader(file);
            char[] chars = new char[(int) file.length()];
            reader.read(chars);
            content = new String(chars);
        } catch (Exception e) {
            LoggerUtil.logINFO(e.toString());
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (Exception e) {
                    LoggerUtil.logINFO(e.toString());
                }
            }
        }
        return content;
    }*/
}

