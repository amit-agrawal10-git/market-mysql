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
public class TaskAttribute extends BaseObject implements Serializable {

    public TaskAttribute(TaskTemplate taskTemplate, Attribute attribute) {
        this.taskTemplate = taskTemplate;
        this.attribute = attribute;
    }

    public TaskAttribute(){}

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
    protected TaskTemplate taskTemplate;

    @ManyToOne(cascade = {
            CascadeType.DETACH,
            CascadeType.MERGE,
            CascadeType.PERSIST,
            CascadeType.REFRESH
    })
    @JoinColumn
    protected Attribute attribute;

    @Column
    protected String defaultValue;

    public TaskTemplate getTaskTemplate() {
        return taskTemplate;
    }

    @JsonIgnore
    public void setDefaultValue(Boolean value) {
        this.defaultValue = value.toString();
    }

    public void setTaskTemplate(TaskTemplate taskTemplate) {
        this.taskTemplate = taskTemplate;
    }

    public Attribute getAttribute() {
        return attribute;
    }

    public void setAttribute(Attribute attribute) {
        this.attribute = attribute;
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

    public Object getDefaultValue() throws Exception {
        Object result = null;
        switch (this.attribute.getType()){
            case STRING:
                result = calculateDefaultValue(defaultValue, attribute.getDefaultValue());
                break;
            case NUMBER:
                result = new BigDecimal(calculateDefaultValue(defaultValue, attribute.getDefaultValue()));
                break;
            case DATE:
                    result = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss").parse(calculateDefaultValue(defaultValue, attribute.getDefaultValue()));
                break;
            case BOOLEAN:
                result = new Boolean(calculateDefaultValue(defaultValue, attribute.getDefaultValue()));
        }
        return result;
    }

    public void setDefaultValue(String defaultValue) {
        this.defaultValue = defaultValue;
    }

    @JsonIgnore
    public void setDefaultValue(Date date) {
        this.defaultValue = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss").format(date);
    }

    @JsonIgnore
    public void setDefaultValue(BigDecimal bigDecimal) {
        this.defaultValue = bigDecimal.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TaskAttribute that = (TaskAttribute) o;
        return Objects.equals(id, that.id) &&
                Objects.equals(taskTemplate, that.taskTemplate) &&
                Objects.equals(attribute, that.attribute) &&
                Objects.equals(defaultValue, that.defaultValue);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, taskTemplate, attribute, defaultValue);
    }

    @Override
    public String toString() {
        return "ProcessTaskAttribute{" +
                "id=" + id +
                ", taskTemplate=" + taskTemplate +
                ", attribute=" + attribute +
                ", defaultValue='" + defaultValue + '\'' +
                '}';
    }
}
