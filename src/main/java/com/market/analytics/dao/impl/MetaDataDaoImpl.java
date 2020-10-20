package com.market.analytics.dao.impl;

import com.market.analytics.dao.MetaDataDao;
import com.market.analytics.entity.metadata.ProcessTaskAttribute;
import com.market.analytics.entity.metadata.TaskAttribute;
import com.market.analytics.entity.process.ProcessTemplate;
import com.market.analytics.entity.process.TaskTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import javax.persistence.EntityManager;
import javax.persistence.Query;
import java.util.List;

@Repository
public class MetaDataDaoImpl extends BaseDaoImpl implements MetaDataDao {

    @Autowired
    EntityManager entityManager;

    @Override
    public List<TaskAttribute> getAllTaskAttributesByTaskTemplate(TaskTemplate taskTemplate) {
        Query theQuery = entityManager.createQuery("from TaskAttribute where taskTemplate=:taskTemplate");
        theQuery.setParameter("taskTemplate",taskTemplate);
        return theQuery.getResultList();

    }

    @Override
    public List<ProcessTaskAttribute> getAllProcessTaskAttributes(ProcessTemplate processTemplate, TaskTemplate taskTemplate) {
        List<TaskAttribute> taskAttributes = this.getAllTaskAttributesByTaskTemplate(taskTemplate);

        Query theQuery = entityManager.createQuery("from ProcessTaskAttribute where taskAttribute in(:taskAttributes)");
        theQuery.setParameter("taskAttributes",taskAttributes);
        return theQuery.getResultList();
    }

    @Override
    public TaskAttribute getTaskAttributeByTaskAndName(TaskTemplate taskTemplate, String Name) {
        Query theQuery = entityManager.createQuery("select TA from TaskAttribute TA JOIN Attribute A ON TA.attribute = A.id where TA.taskTemplate=:taskTemplate and A.name = :name");
        theQuery.setParameter("taskTemplate",taskTemplate);
        theQuery.setParameter("name",Name);
        return (TaskAttribute)(theQuery.getResultList().isEmpty()?null:theQuery.getResultList().get(0));
    }

    @Override
    public ProcessTaskAttribute getProcessTaskAttributeByTaskAttr(ProcessTemplate processTemplate,TaskAttribute taskAttribute) {
        Query theQuery = entityManager.createQuery("from ProcessTaskAttribute where taskAttribute=:taskAttribute and processTemplate=:processTemplate");
        theQuery.setParameter("taskAttribute",taskAttribute);
        theQuery.setParameter("processTemplate",processTemplate);
        return (ProcessTaskAttribute)(theQuery.getResultList().isEmpty()?null:theQuery.getResultList().get(0));
    }
}
