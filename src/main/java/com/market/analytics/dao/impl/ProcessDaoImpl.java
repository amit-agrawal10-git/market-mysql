package com.market.analytics.dao.impl;

import com.market.analytics.dao.ProcessDao;
import com.market.analytics.entity.process.Process;
import com.market.analytics.entity.process.ProcessStatus;
import com.market.analytics.entity.metadata.ProcessType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import javax.persistence.EntityManager;
import javax.persistence.Query;
import java.util.List;

@Repository
public class ProcessDaoImpl extends BaseDaoImpl implements ProcessDao {

    @Autowired
    EntityManager entityManager;

    @Override
    public List<Process> getActiveProcess() {
        Query theQuery = entityManager.createQuery("from Process where enabled=:enabled");
        theQuery.setParameter("enabled",true);
        return theQuery.getResultList();
    }

    @Override
    public ProcessStatus getProcessStatusByType(ProcessType processType) {
        Query theQuery = entityManager.createQuery("from ProcessStatus where type=:processType");
        theQuery.setParameter("processType",processType);
        return (ProcessStatus) (theQuery.getResultList().isEmpty()?null:theQuery.getResultList().get(0));

    }

    @Override
    public Process getProcessByType(ProcessType processType) {
        Query theQuery = entityManager.createQuery("from Process where type=:processType");
        theQuery.setParameter("processType",processType);
        return (Process) (theQuery.getResultList().isEmpty()?null:theQuery.getResultList().get(0));
    }
}
