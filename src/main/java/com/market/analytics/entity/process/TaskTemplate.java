package com.market.analytics.entity.process;

import com.market.analytics.entity.BaseObject;

import javax.persistence.*;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.Objects;

@Entity
public class TaskTemplate extends BaseObject implements Serializable {

    public TaskTemplate(){}
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    protected BigInteger id;

    @Column(unique = true)
    protected String actionClass;

    @Column
    protected String actionMethod;

    public BigInteger getId() {
        return id;
    }

    public void setId(BigInteger id) {
        this.id = id;
    }

    public String getActionMethod() {
        return actionMethod;
    }

    public void setActionMethod(String actionMethod) {
        this.actionMethod = actionMethod;
    }

    @Override
    public String toString() {
        return "TaskTemplate{" +
                "id=" + id +
                ", actionClass='" + actionClass + '\'' +
                ", actionMethod='" + actionMethod + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TaskTemplate that = (TaskTemplate) o;
        return Objects.equals(id, that.id) &&
                Objects.equals(actionClass, that.actionClass) &&
                Objects.equals(actionMethod, that.actionMethod);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, actionClass, actionMethod);
    }

    public String getActionClass() {
        return actionClass;
    }

    public void setActionClass(String actionClass) {
        this.actionClass = actionClass;
    }

    public TaskTemplate(String actionClass, String actionMethod) {
        this.actionClass = actionClass;
        this.actionMethod = actionMethod;
    }
}
