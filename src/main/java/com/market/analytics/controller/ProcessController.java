package com.market.analytics.controller;

import com.market.analytics.entity.metadata.ProcessType;
import com.market.analytics.entity.process.Process;
import com.market.analytics.entity.process.ProcessTemplate;
import com.market.analytics.process.context.Context;
import com.market.analytics.process.initiater.Processor;
import com.market.analytics.service.ProcessManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.List;

@Controller
@RequestMapping("/process")
public class ProcessController {
    private static final Logger logger = LoggerFactory.getLogger(ProcessController.class);

    @Autowired
    @Qualifier("processContext")
    private Context context;

    @Autowired
    private ProcessManager processManager;

    @GetMapping("/start")
    public String execute(Model model) throws ClassNotFoundException,NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {
        List<Process> activeProcess = processManager.getActiveProcess();
        logger.debug("Active process count: "+activeProcess.size());
        for (Process process : activeProcess){
            ProcessTemplate processTemplate = process.getProcessTemplate();
            Class clazz = Class.forName(processTemplate.getInstanceClass());
            Method method = clazz.getMethod(processTemplate.getInstanceMethod(),new Class[]{});
            Processor processor = (Processor) method.invoke(null,null);
            if(!processor.isRunning()){
                logger.debug("Starting new thread for "+processor.getClass().getSimpleName());
                processor.setProcess(process);
                processor.setContext(context);
                (new Thread(processor)).start();
            }
        }
        return "redirect:/stock/list";
    }

    @GetMapping("/new")
    public String newProcess(Model model){
        model.addAttribute("type", ProcessType.values());
        return "newprocess";
    }

}
