package com.market.analytics.process.action;

import com.market.analytics.entity.process.TaskTemplate;
import com.market.analytics.process.context.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Set;

@Component
public class TaskExecutor {

    private static final Logger logger = LoggerFactory.getLogger(TaskExecutor.class);

    public static void perform(Context context, TaskTemplate taskTemplate, Object input) throws InstantiationException,IllegalAccessException, InvocationTargetException, ClassNotFoundException, NoSuchMethodException
    {
        Class clazz = Class.forName(taskTemplate.getActionClass());
        Method method = clazz.getMethod(taskTemplate.getActionMethod(),new Class[]{Context.class, TaskTemplate.class, Object.class});
        Object output = method.invoke(clazz,context, taskTemplate, input);
        Set<TaskTemplate> nextTasks = context.getProcessManager().getNextTaskTemplates(context.getProcessTemplate(),taskTemplate);
        for (TaskTemplate taskTemp:nextTasks) {
            perform(context, taskTemp, output);
        }

    }

}
