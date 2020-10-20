package com.market.analytics.dao;

import com.market.analytics.entity.metadata.ProcessTaskAttribute;
import com.market.analytics.entity.metadata.TaskAttribute;
import com.market.analytics.entity.process.ProcessTemplate;
import com.market.analytics.entity.process.TaskTemplate;

import java.util.List;

public interface MetaDataDao extends Dao {

    List<TaskAttribute> getAllTaskAttributesByTaskTemplate(TaskTemplate taskTemplate);
    List<ProcessTaskAttribute> getAllProcessTaskAttributes(ProcessTemplate processTemplate, TaskTemplate taskTemplate);
    TaskAttribute getTaskAttributeByTaskAndName(TaskTemplate taskTemplate, String Name);
    ProcessTaskAttribute getProcessTaskAttributeByTaskAttr(ProcessTemplate processTemplate, TaskAttribute taskAttribute);

}
