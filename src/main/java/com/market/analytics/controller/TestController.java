package com.market.analytics.controller;

import com.market.analytics.dao.repository.StockRepository;
import com.market.analytics.entity.Stock;
import com.market.analytics.kra.KRASOAPValidationTest;
import com.market.analytics.process.context.Context;
import com.market.analytics.service.MetaDataManager;
import com.market.analytics.service.ProcessManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@RestController
public class TestController {

    private static final Logger logger = LoggerFactory.getLogger(TestController.class);

    @Autowired
    private ProcessManager processManager;

    @Autowired
    private StockRepository stockRepository;

    @Autowired
    private MetaDataManager metaDataManager;

    @Autowired
    protected Context context;

    @GetMapping("/prepare")
    public String prepareTestData(){
        /*TaskTemplate taskTemplate = new TaskTemplate("com.market.analytics.process.action.URLBuilderAction","execute");
        UploadType uploadType = uploadManager.getUploadTypeByType(UploadDataType.STOCK_BHAV);
        TaskTemplate2TaskTemplate templateMapping = new TaskTemplate2TaskTemplate(uploadType.getProcessTemplate(), null, taskTemplate);
        uploadManager.persist(templateMapping);*/

     /*   Attribute URLPrefix = new Attribute("URLPrefix", AttributeType.STRING);
        Attribute URLSuffix = new Attribute("URLSuffix", AttributeType.STRING);
        Attribute DateMacro = new Attribute("DateMacro", AttributeType.STRING);
        Attribute ToUpperCase = new Attribute("ToUpperCase", AttributeType.BOOLEAN);
        ToUpperCase.setDefaultValue(false);
        UploadType uploadType = uploadManager.getUploadTypeByType(UploadDataType.STOCK_BHAV);
        TaskTemplate taskTemplate = processManager.getTaskTemplateByActionClass("com.market.analytics.process.action.URLBuilderAction");

        TaskAttribute URLPrefixTaskAttribute = new TaskAttribute(taskTemplate, URLPrefix);
        TaskAttribute URLSuffixTaskAttribute = new TaskAttribute(taskTemplate, URLSuffix);
        TaskAttribute DateMacroTaskAttribute = new TaskAttribute(taskTemplate, DateMacro);
        TaskAttribute ToUpperCaseTaskAttribute = new TaskAttribute(taskTemplate, ToUpperCase);
        ToUpperCaseTaskAttribute.setDefaultValue(true);

        ProcessTaskAttribute prefixTaskAttribute =
                new ProcessTaskAttribute(uploadType.getProcessTemplate(),URLPrefixTaskAttribute);
        prefixTaskAttribute.setValue("content/historical/EQUITIES/");

        ProcessTaskAttribute suffixTaskAttribute = new ProcessTaskAttribute(uploadType.getProcessTemplate(), URLSuffixTaskAttribute);
        suffixTaskAttribute.setValue("bhav.csv.zip");

        ProcessTaskAttribute DateMacroProcessTaskAttribute = new ProcessTaskAttribute(uploadType.getProcessTemplate(), DateMacroTaskAttribute);
        DateMacroProcessTaskAttribute.setValue("<yyyy/MMM>/cm<ddMMMyyyy>");

        metaDataManager.persist(DateMacroProcessTaskAttribute);
        metaDataManager.persist(suffixTaskAttribute);
        metaDataManager.persist(prefixTaskAttribute);
        metaDataManager.persist(ToUpperCaseTaskAttribute);

*/

        logger.info("All objects are saved");
        return "redirect:/stock/list";
    }

    @GetMapping("/kra")
    public List<Stock> kra() throws Exception{

        KRASOAPValidationTest.validate("src/main/java/com/market/analytics/kra/orig.kra.response");

        return stockRepository.findAll();
    }

    @GetMapping("/test")
    public List<Stock> test(){
        return stockRepository.findAll();
    }

    public static void main(String[] args) {
       String s = "<yyyy/MMM>/cm<ddMMMyyyy>";
       Pattern p = Pattern.compile("<[\\w/]+>");
       Matcher m = p.matcher(s);
       while (m.find()){
           System.out.println(m.group());
       }


    }


}
