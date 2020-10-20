package com.market.analytics.process.action;

import com.market.analytics.entity.process.TaskTemplate;
import com.market.analytics.process.context.Context;
import com.market.analytics.utility.Constants;
import com.market.analytics.utility.Downloader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class URLDownloadAction {

    private static final Logger logger = LoggerFactory.getLogger(URLDownloadAction.class);

    public static Object execute(Context context, TaskTemplate taskTemplate, Object input) throws Exception {
        String formattedURL = input.toString();
        String fileName = formattedURL.substring(formattedURL.lastIndexOf("/")+1);
        String fileAbsolutePath = Downloader.downloadFile(formattedURL,Constants.TEMP_FOLDER,fileName, null);
        if (fileAbsolutePath == null)
            throw new RuntimeException("Corresponding file could not be downloaded");
        logger.debug("File Absolute Path "+fileAbsolutePath);
        return fileAbsolutePath;
    }

}
