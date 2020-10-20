package com.market.analytics.dao;

import com.market.analytics.entity.process.ProcessTemplate;
import com.market.analytics.entity.process.TaskTemplate;

import java.math.BigInteger;
import java.util.Set;

public interface ProcessTemplateDao extends Dao {

    public Set<TaskTemplate> getNextTaskTemplates(ProcessTemplate processTemplate, TaskTemplate taskTemplate);
    public TaskTemplate getFirstTaskByProcess(ProcessTemplate processTemplate);
}
