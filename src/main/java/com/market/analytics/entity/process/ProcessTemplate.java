package com.market.analytics.entity.process;

import com.market.analytics.entity.BaseObject;

import javax.persistence.*;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.Objects;

@Entity
public class ProcessTemplate extends BaseObject implements Serializable {
    public ProcessTemplate(){}

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    protected BigInteger id;

    @Column
    protected String instanceClass;

    @Column
    protected String instanceMethod;

    @OneToOne(mappedBy = "processTemplate")
    protected Process process;

    public BigInteger getId() {
        return id;
    }

    public void setId(BigInteger id) {
        this.id = id;
    }

    public ProcessTemplate(String instanceClass, String instanceMethod) {
        this.instanceClass = instanceClass;
        this.instanceMethod = instanceMethod;
    }

    public Process getProcess(){
        return this.process;
    }

    public String getInstanceClass() {
        return instanceClass;
    }

    public void setInstanceClass(String instanceClass) {
        this.instanceClass = instanceClass;
    }

    public String getInstanceMethod() {
        return instanceMethod;
    }

    public void setInstanceMethod(String instanceMethod) {
        this.instanceMethod = instanceMethod;
    }

    @Override
    public String toString() {
        return "ProcessTemplate{" +
                "id=" + id +
                ", instanceClass='" + instanceClass + '\'' +
                ", instanceMethod='" + instanceMethod + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ProcessTemplate that = (ProcessTemplate) o;
        return Objects.equals(id, that.id) &&
                Objects.equals(instanceClass, that.instanceClass) &&
                Objects.equals(instanceMethod, that.instanceMethod);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, instanceClass, instanceMethod);
    }
}
