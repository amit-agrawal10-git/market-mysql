package com.market.analytics.service.impl;

import com.market.analytics.dao.ProcessDao;
import com.market.analytics.dao.ProcessTemplateDao;
import com.market.analytics.dao.TaskTemplateDao;
import com.market.analytics.entity.process.Process;
import com.market.analytics.entity.process.ProcessStatus;
import com.market.analytics.entity.metadata.ProcessType;
import com.market.analytics.entity.process.ProcessTemplate;
import com.market.analytics.entity.process.TaskTemplate;
import com.market.analytics.service.ProcessManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Set;

@Service
@Transactional
public class ProcessManagerImpl implements ProcessManager {

    @Autowired
    private ProcessTemplateDao processTemplateDao;

    @Autowired
    private TaskTemplateDao taskTemplateDao;

    @Autowired
    private ProcessDao processDao;

    @Override
    public TaskTemplate getTaskTemplateByActionClass(String actionClass) {
        return taskTemplateDao.getTaskTemplateByActionClass(actionClass);
    }

    @Override
    public Set<TaskTemplate> getNextTaskTemplates(ProcessTemplate processTemplate, TaskTemplate taskTemplate) {
        return processTemplateDao.getNextTaskTemplates(processTemplate,taskTemplate);
    }

    @Override
    public TaskTemplate getFirstTaskByProcess(ProcessTemplate processTemplate) {
        return processTemplateDao.getFirstTaskByProcess(processTemplate);
    }

    @Override
    public List<Process> getActiveProcess() {
        return processDao.getActiveProcess();
    }

    @Override
    public ProcessStatus getProcessStatusByType(ProcessType processType) {
        return processDao.getProcessStatusByType(processType);
    }

    @Override
    public Process getProcessByType(ProcessType processType) {
        return processDao.getProcessByType(processType);
    }
}
