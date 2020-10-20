package com.market.analytics.process.action;

import com.market.analytics.entity.process.ProcessTemplate;
import com.market.analytics.entity.process.TaskTemplate;
import com.market.analytics.process.context.Context;
import com.market.analytics.service.MetaDataManager;
import com.market.analytics.utility.Constants;
import com.market.analytics.utility.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class URLBuilderAction {

    private static final Logger logger = LoggerFactory.getLogger(URLBuilderAction.class);

    public static Object execute(Context context, TaskTemplate taskTemplate, Object input) throws Exception {
        Date date = (Date)input;
        StringBuilder formattedURL = new StringBuilder(Constants.NSE_SITE_URL);
        ProcessTemplate processTemplate = context.getProcessTemplate();
        MetaDataManager metaDataManager = context.getMetaDataManager();

        String URLPrefix = (String) metaDataManager.getProcessTaskAttrValue(processTemplate,taskTemplate,"URLPrefix");
        String URLSuffix = (String) metaDataManager.getProcessTaskAttrValue(processTemplate,taskTemplate,"URLSuffix");
        String DateMacro = (String) metaDataManager.getProcessTaskAttrValue(processTemplate,taskTemplate,"DateMacro");
        Boolean ToUpperCase = (Boolean) metaDataManager.getProcessTaskAttrValue(processTemplate,taskTemplate,"ToUpperCase");
        formattedURL
                .append(URLPrefix)
                .append(prepareDateString(DateMacro,date,ToUpperCase))
                .append(URLSuffix);
        logger.debug("Final formatted URL: "+formattedURL.toString());
        return formattedURL;
    }

    private static String prepareDateString(String input, Date date, Boolean toUpperCase) throws Exception{
        String match = null;
        Pattern p = Pattern.compile("<[\\w/]+>");
        Matcher m = p.matcher(input);
        while (m.find()){
            match = m.group();
            input = input.replace(match, (toUpperCase)?Utils.formatDate(date,match.substring(1,match.length()-1)).toUpperCase():Utils.formatDate(date,match.substring(1,match.length()-1)) );
        }
        return input;
    }
}
