package com.market.analytics.dao.impl;

import com.market.analytics.dao.ProcessTemplateDao;
import com.market.analytics.dao.TaskTemplateDao;
import com.market.analytics.entity.process.ProcessTemplate;
import com.market.analytics.entity.process.TaskTemplate;
import com.market.analytics.entity.process.TaskTemplate2TaskTemplate;
import org.hibernate.Session;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import javax.persistence.EntityManager;
import javax.persistence.Query;
import java.math.BigInteger;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Repository
public class ProcessTemplateDaoImpl extends BaseDaoImpl implements ProcessTemplateDao {

    @Autowired
    EntityManager entityManager;

    @Override
    public TaskTemplate getFirstTaskByProcess(ProcessTemplate processTemplate) {
        Query theQuery = entityManager.createQuery("from TaskTemplate2TaskTemplate where processTemplate=:processTemplate and fromTaskTemplate is null");
        theQuery.setParameter("processTemplate",processTemplate);
        List<TaskTemplate2TaskTemplate> taskTemplate2TaskTemplates = theQuery.getResultList();
        return (taskTemplate2TaskTemplates.isEmpty())?null:taskTemplate2TaskTemplates.get(0).getToTaskTemplate();
    }

    @Override
    public Set<TaskTemplate> getNextTaskTemplates(ProcessTemplate processTemplate, TaskTemplate taskTemplate) {
        Query theQuery = entityManager.createQuery("from TaskTemplate2TaskTemplate where processTemplate=:processTemplate and fromTaskTemplate=:fromTaskTemplate");
        theQuery.setParameter("processTemplate",processTemplate);
        theQuery.setParameter("fromTaskTemplate",taskTemplate);
        List<TaskTemplate2TaskTemplate> taskTemplate2TaskTemplates = theQuery.getResultList();
        Set<TaskTemplate> taskTemplates = new HashSet<TaskTemplate>();

        for (TaskTemplate2TaskTemplate template:taskTemplate2TaskTemplates) {
            taskTemplates.add(template.getToTaskTemplate());
        }
        return taskTemplates;
    }
}
