package com.market.analytics.dao;

import com.market.analytics.entity.process.TaskTemplate;

public interface TaskTemplateDao extends Dao {

    public TaskTemplate getTaskTemplateByActionClass(String actionClass);

}
