package com.market.analytics.process.initiater;

import com.market.analytics.entity.process.ProcessStatus;
import com.market.analytics.entity.process.TaskTemplate;
import com.market.analytics.process.action.TaskExecutor;
import com.market.analytics.utility.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.util.Calendar;
import java.util.Date;

public class IndexBhavUploadProcessor extends Processor {

    private static final Logger logger = LoggerFactory.getLogger(IndexBhavUploadProcessor.class);
    private boolean isRunning;

    private IndexBhavUploadProcessor(){}

    private static class Impl
    {
        private static final IndexBhavUploadProcessor INSTANCE = new IndexBhavUploadProcessor();
    }

    public static Executable getInstance(){
        return Impl.INSTANCE;
    }

    @Override
    public boolean isRunning() {
        return isRunning;
    }

    @Override
    public void run() {
        isRunning = true;

        try{
            MDC.put("logFileName", this.getClass().getSimpleName());
            ProcessStatus processStatus = this.getProcess().getProcessStatus();
            this.getContext().setProcessTemplate(this.getProcess().getProcessTemplate());
            TaskTemplate firstTaskTemplate = this.getContext().getProcessManager().getFirstTaskByProcess(this.getProcess().getProcessTemplate());

            Date startDate = (processStatus.getExecutedupto()== null)?processStatus.getStartDate():processStatus.getExecutedupto();
            Calendar start = Calendar.getInstance();
            start.setTime(startDate);
            start.add(Calendar.DATE, 1);
            Calendar end = Calendar.getInstance();
            end.setTime(new Date());

            for (Date date = start.getTime(); start.before(end); start.add(Calendar.DATE, 1),
                    date = start.getTime()) {
                    if(!Utils.isWeekend(date)){
                        try{
                            MDC.put("date",Utils.formatDate(date,"yyyy-MM-dd"));
                            getContext().setContextValue("date",date);
                            TaskExecutor.perform(this.getContext(), firstTaskTemplate, date);
                            processStatus.setExecutedupto(date);
                            this.getContext().getManager().save(processStatus);
                        } catch (Exception exception){
                            logger.error(exception.getMessage(),exception);
                        }
                    }
            }
        } finally {
            isRunning = false;
            MDC.clear();
        }
    }
}
