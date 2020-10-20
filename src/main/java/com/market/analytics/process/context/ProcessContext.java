package com.market.analytics.process.context;

import com.market.analytics.entity.process.ProcessTemplate;
import com.market.analytics.service.Manager;
import com.market.analytics.service.MetaDataManager;
import com.market.analytics.service.ProcessManager;
import com.market.analytics.service.ScripManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
@Scope("prototype")
public class ProcessContext implements Context {

    private Map<String,Object> map = new HashMap();
    private ProcessTemplate processTemplate;

    @Autowired
    @Qualifier("baseManagerImpl")
    private Manager manager;

    @Autowired
    private ScripManager scripManager;

    @Autowired
    private MetaDataManager metaDataManager;

    @Autowired
    private ProcessManager processManager;

    @Override
    public ProcessTemplate getProcessTemplate() {
        return processTemplate;
    }

    public void setProcessTemplate(ProcessTemplate processTemplate) {
        this.processTemplate = processTemplate;
    }

    public ProcessManager getProcessManager() {
        return processManager;
    }

    public MetaDataManager getMetaDataManager() {
        return metaDataManager;
    }

    public Manager getManager() {
        return manager;
    }

    @Override
    public ScripManager getScripManager() {
        return scripManager;
    }

    public Object getContextValue(String key) {
        return map.get(key);
    }

    public void setContextValue(String key,Object value) {
        map.put(key,value);
    }
}
