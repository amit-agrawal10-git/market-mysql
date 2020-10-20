package com.market.analytics.process.context;

import com.market.analytics.entity.process.ProcessTemplate;
import com.market.analytics.service.Manager;
import com.market.analytics.service.MetaDataManager;
import com.market.analytics.service.ProcessManager;
import com.market.analytics.service.ScripManager;

public interface Context {
    public ProcessTemplate getProcessTemplate();
    public ProcessManager getProcessManager();
    public MetaDataManager getMetaDataManager();
    public Manager getManager();
    public ScripManager getScripManager();
    public Object getContextValue(String key);
    public void setContextValue(String key,Object value);
    public void setProcessTemplate(ProcessTemplate processTemplate);

}
