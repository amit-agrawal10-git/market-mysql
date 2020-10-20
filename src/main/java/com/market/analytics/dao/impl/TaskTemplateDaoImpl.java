package com.market.analytics.dao.impl;

import com.market.analytics.dao.TaskTemplateDao;
import com.market.analytics.entity.process.TaskTemplate;
import com.market.analytics.entity.process.TaskTemplate2TaskTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import javax.persistence.EntityManager;
import javax.persistence.Query;
import java.math.BigInteger;
import java.util.List;

@Repository
public class TaskTemplateDaoImpl extends BaseDaoImpl implements TaskTemplateDao {

    @Autowired
    EntityManager entityManager;

    @Override
    public TaskTemplate getTaskTemplateByActionClass(String actionClass) {
        Query theQuery = entityManager.createQuery("from TaskTemplate where actionClass=:actionClass");
        theQuery.setParameter("actionClass",actionClass);
        return (TaskTemplate)( (theQuery.getResultList().isEmpty())?null:theQuery.getResultList().get(0));
    }
}
