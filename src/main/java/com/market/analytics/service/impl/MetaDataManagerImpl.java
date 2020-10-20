package com.market.analytics.service.impl;

import com.market.analytics.dao.MetaDataDao;
import com.market.analytics.entity.metadata.ProcessTaskAttribute;
import com.market.analytics.entity.metadata.TaskAttribute;
import com.market.analytics.entity.process.ProcessTemplate;
import com.market.analytics.entity.process.TaskTemplate;
import com.market.analytics.service.MetaDataManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional
public class MetaDataManagerImpl implements MetaDataManager {

    @Autowired
    private MetaDataDao metaDataDao;

    @Override
    public List<TaskAttribute> getAllTaskAttributesByTaskTemplate(TaskTemplate taskTemplate) {
        return metaDataDao.getAllTaskAttributesByTaskTemplate(taskTemplate);
    }

    @Override
    public List<ProcessTaskAttribute> getAllProcessTaskAttributes(ProcessTemplate processTemplate, TaskTemplate taskTemplate) {
        return metaDataDao.getAllProcessTaskAttributes(processTemplate, taskTemplate);
    }

    @Override
    public TaskAttribute getTaskAttributeByTaskAndName(TaskTemplate taskTemplate, String Name) {
        return metaDataDao.getTaskAttributeByTaskAndName(taskTemplate, Name);
    }

    @Override
    public ProcessTaskAttribute getProcessTaskAttributeByTaskAttr(ProcessTemplate processTemplate, TaskAttribute taskAttribute) {
        return metaDataDao.getProcessTaskAttributeByTaskAttr(processTemplate, taskAttribute);
    }

    @Override
    public Object getProcessTaskAttrValue(ProcessTemplate processTemplate, TaskTemplate taskTemplate, String Name) throws Exception {
        TaskAttribute taskAttribute = getTaskAttributeByTaskAndName(taskTemplate, Name);
        ProcessTaskAttribute processTaskAttribute = getProcessTaskAttributeByTaskAttr(processTemplate, taskAttribute);
        if(processTaskAttribute!=null)
            return processTaskAttribute.getValue();
        return taskAttribute.getDefaultValue();
    }
}
