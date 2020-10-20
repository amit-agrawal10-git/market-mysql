package com.market.analytics.service;

import com.market.analytics.entity.process.Process;
import com.market.analytics.entity.process.ProcessStatus;
import com.market.analytics.entity.metadata.ProcessType;
import com.market.analytics.entity.process.ProcessTemplate;
import com.market.analytics.entity.process.TaskTemplate;

import java.util.List;
import java.util.Set;

public interface ProcessManager {

    public Set<TaskTemplate> getNextTaskTemplates(ProcessTemplate processTemplate, TaskTemplate taskTemplate);
    public TaskTemplate getFirstTaskByProcess(ProcessTemplate processTemplate);
    public TaskTemplate getTaskTemplateByActionClass(String actionClass);
    public List<Process> getActiveProcess();
    public ProcessStatus getProcessStatusByType(ProcessType processType);
    public Process getProcessByType(ProcessType processType);

}
