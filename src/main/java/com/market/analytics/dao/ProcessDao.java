package com.market.analytics.dao;

import com.market.analytics.entity.process.Process;
import com.market.analytics.entity.process.ProcessStatus;
import com.market.analytics.entity.metadata.ProcessType;

import java.util.List;

public interface ProcessDao extends Dao {

    public List<Process> getActiveProcess();
    public ProcessStatus getProcessStatusByType(ProcessType processType);
    public Process getProcessByType(ProcessType processType);
}
