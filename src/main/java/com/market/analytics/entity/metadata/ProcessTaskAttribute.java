package com.market.analytics.entity.metadata;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.market.analytics.entity.BaseObject;
import com.market.analytics.entity.process.ProcessTemplate;
import com.market.analytics.entity.process.TaskTemplate;

import javax.persistence.*;
import java.io.Serializable;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Objects;

@Entity
public class ProcessTaskAttribute extends BaseObject implements Serializable {

    public ProcessTaskAttribute(){}
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    protected BigInteger id;

    @ManyToOne(cascade = {
            CascadeType.DETACH,
            CascadeType.MERGE,
            CascadeType.PERSIST,
            CascadeType.REFRESH
    })
    @JoinColumn
    protected ProcessTemplate processTemplate;

    @ManyToOne(cascade = {
            CascadeType.DETACH,
            CascadeType.MERGE,
            CascadeType.PERSIST,
            CascadeType.REFRESH
    })
    @JoinColumn
    protected TaskAttribute taskAttribute;

    @Column
    protected String value;

    public TaskAttribute getTaskAttribute() {
        return taskAttribute;
    }

    public void setTaskAttribute(TaskAttribute taskAttribute) {
        this.taskAttribute = taskAttribute;
    }

    public ProcessTemplate getProcessTemplate() {
        return processTemplate;
    }

    public void setProcessTemplate(ProcessTemplate processTemplate) {
        this.processTemplate = processTemplate;
    }

    private String calculateDefaultValue(String processDefault, Object attributeDefault){
        if(processDefault!=null){
            return processDefault;
        }
        if(attributeDefault!=null){
            return attributeDefault.toString();
        }
        return null;
    }

    public Object getValue() throws Exception {
        Object result = null;
        switch (this.getTaskAttribute().getAttribute().getType()){
            case STRING:
                result = calculateDefaultValue(value, this.getTaskAttribute().getDefaultValue());
                break;
            case NUMBER:
                result = new BigDecimal(calculateDefaultValue(value, this.getTaskAttribute().getDefaultValue()));
                break;
            case DATE:
                result = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss").parse(calculateDefaultValue(value, this.getTaskAttribute().getDefaultValue()));
                break;
            case BOOLEAN:
                result = new Boolean(calculateDefaultValue(value, this.getTaskAttribute().getDefaultValue()));
        }
        return result;
    }

    public void setValue(String defaultValue) {
        this.value = defaultValue;
    }

    @JsonIgnore
    public void setValue(Date date) {
        this.value = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss").format(date);
    }

    @JsonIgnore
    public void setValue(BigDecimal bigDecimal) {
        this.value = bigDecimal.toString();
    }

    @JsonIgnore
    public void setValue(Boolean value) {
        this.value = value.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ProcessTaskAttribute that = (ProcessTaskAttribute) o;
        return Objects.equals(id, that.id) &&
                Objects.equals(processTemplate, that.processTemplate) &&
                Objects.equals(taskAttribute, that.taskAttribute) &&
                Objects.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, processTemplate, taskAttribute, value);
    }

    @Override
    public String toString(){
        return "ProcessTaskAttribute{" +
                "id=" + id +
                ", processTemplate=" + processTemplate +
                ", taskAttribute=" + taskAttribute +
                '}';
    }

    public ProcessTaskAttribute(ProcessTemplate processTemplate, TaskAttribute taskAttribute) {
        this.processTemplate = processTemplate;
        this.taskAttribute = taskAttribute;
    }
}
