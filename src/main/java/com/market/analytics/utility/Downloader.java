package com.market.analytics.utility;

import org.springframework.http.HttpHeaders;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;


public class Downloader {

    private static int BUFFER_SIZE = 4096;
    private static Map<String,String> HTTP_HEADERS = new HashMap<String, String>();

    static{
        HTTP_HEADERS.put(HttpHeaders.USER_AGENT,"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36");
        HTTP_HEADERS.put(HttpHeaders.ACCEPT, "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3");
        // HTTP_HEADERS.put(HttpHeaders.ACCEPT_ENCODING, "gzip, deflate, sdch, br");
        HTTP_HEADERS.put(HttpHeaders.ACCEPT_LANGUAGE, "fr-FR,fr;q=0.8,en-US;q=0.6,en;q=0.4");
        HTTP_HEADERS.put("Sec-Fetch-Mode","navigate");
        HTTP_HEADERS.put("Sec-Fetch-Site","same-origin");
        HTTP_HEADERS.put("Sec-Fetch-User","?1");
        HTTP_HEADERS.put(HttpHeaders.HOST, "www.nseindia.com:443");
        HTTP_HEADERS.put("Upgrade-Insecure-Requests", "1");
        HTTP_HEADERS.put(HttpHeaders.CONNECTION, "keep-alive");
        HTTP_HEADERS.put(HttpHeaders.REFERER, "https://www.nseindia.com/");
    }

    public static String getHeaderValue(String key, String defaultValue, Map<String,String> userHeaders){
        return (userHeaders!= null && userHeaders.containsKey(key)?userHeaders.get(key):defaultValue);
    }

    public static void setHeaders(HttpURLConnection connection, HashMap<String,String> headers){
        HTTP_HEADERS.keySet()
                .stream()
                .forEach(s ->
                        connection.setRequestProperty(s,
                                getHeaderValue(s,
                                        HTTP_HEADERS.get(s),
                                        headers)));
    }

    public static String downloadFile(String fileURL, String filePath, String fName, HashMap<String,String> headers) throws IOException
    {

        String filePathName = filePath+File.separator+fName;
        File file = new File(filePathName);
        if(file.exists()){
            return file.getCanonicalPath();
        }
        InputStream inputStream = null;
        FileOutputStream outputStream = null;
        HttpURLConnection httpConn = null;
        try {

            URL url = new URL(fileURL);
            httpConn = (HttpURLConnection) url.openConnection();
            setHeaders(httpConn,headers);
            httpConn.setRequestMethod("GET");
            int responseCode = httpConn.getResponseCode();
            // always check HTTP response code first
            if (responseCode == HttpURLConnection.HTTP_OK && httpConn.getContentLength() > -1) {
                // opens input stream from the HTTP connection
                inputStream = httpConn.getInputStream();
                new File(filePath).mkdirs();

                // opens an output stream to save into file
                outputStream = new FileOutputStream(filePathName);
                int bytesRead = -1;
                byte[] buffer = new byte[BUFFER_SIZE];
                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    outputStream.write(buffer, 0, bytesRead);
                }
                file = new File(filePathName);
            }
        } finally {
            if(outputStream!=null)
                outputStream.close();
            if (inputStream!=null)
                inputStream.close();
            if(httpConn!=null)
                httpConn.disconnect();
        }
        return (file.exists())?file.getCanonicalPath():null;
    }
}
