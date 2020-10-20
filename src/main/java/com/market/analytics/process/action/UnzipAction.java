package com.market.analytics.process.action;

import com.market.analytics.entity.process.TaskTemplate;
import com.market.analytics.process.context.Context;
import com.market.analytics.utility.ZipUtility;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;

public class UnzipAction {

    private static final Logger logger = LoggerFactory.getLogger(UnzipAction.class);

    public static Object execute(Context context, TaskTemplate taskTemplate, Object input) throws Exception {
        String filePath = input.toString();
        String newFilePath = filePath.replace(".zip","");
        File newFile = new File(newFilePath);

        if(!newFile.exists()) {
            File file = new File(filePath);
            ZipUtility.unZipIt(file.getName(),file.getParent());
            newFile = new File(newFilePath);
        }
        if (!newFile.exists())
            throw new RuntimeException("Unzip failed!!");
        logger.debug("Was unzip succeeded? "+newFile.exists()+ " , file is present in "+newFile.getCanonicalPath());
        return newFile.getCanonicalPath();
    }

}
