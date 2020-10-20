package com.market.analytics.process.action;

import com.market.analytics.entity.process.ProcessTemplate;
import com.market.analytics.entity.process.TaskTemplate;
import com.market.analytics.process.context.Context;
import com.market.analytics.service.MetaDataManager;
import com.market.analytics.utility.CSVParserUtil;
import org.apache.commons.csv.CSVRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public class ParseCSVAction {

    private static final Logger logger = LoggerFactory.getLogger(ParseCSVAction.class);

    public static Object execute(Context context, TaskTemplate taskTemplate, Object input) throws Exception {
        String fileAbsolutePath = input.toString();
        ProcessTemplate processTemplate = context.getProcessTemplate();
        MetaDataManager metaDataManager = context.getMetaDataManager();
        String CSVFileHeaders = (String) metaDataManager.getProcessTaskAttrValue(processTemplate,taskTemplate,"CSVFileHeaders");
        String[] headers = CSVFileHeaders.split(",");
        List<CSVRecord> csvRecords = CSVParserUtil.parseCSVFile(fileAbsolutePath,headers);
        if (csvRecords.size()==0)
            throw new RuntimeException("Nothing found in CSV file");

        logger.debug("CSV Record count "+csvRecords.size());
        return csvRecords;
    }

}
