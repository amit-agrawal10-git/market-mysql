package com.market.analytics.entity.process;

import com.market.analytics.entity.BaseObject;

import javax.persistence.*;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.Objects;

@Entity
public class TaskTemplate2TaskTemplate extends BaseObject implements Serializable {

    public TaskTemplate2TaskTemplate(ProcessTemplate processTemplate, TaskTemplate fromTaskTemplate, TaskTemplate toTaskTemplate) {
        this.processTemplate = processTemplate;
        this.fromTaskTemplate = fromTaskTemplate;
        this.toTaskTemplate = toTaskTemplate;
    }

    public TaskTemplate2TaskTemplate(){}
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    protected BigInteger id;

    @ManyToOne(cascade = {
            CascadeType.DETACH,
            CascadeType.MERGE,
            CascadeType.PERSIST,
            CascadeType.REFRESH
    })
    @JoinColumn(name = "process_template_id")
    protected ProcessTemplate processTemplate;

    @ManyToOne(cascade = {
            CascadeType.DETACH,
            CascadeType.MERGE,
            CascadeType.PERSIST,
            CascadeType.REFRESH
    })
    @JoinColumn(name = "from_task_template_id")
    protected TaskTemplate fromTaskTemplate;

    @ManyToOne(cascade = {
            CascadeType.DETACH,
            CascadeType.MERGE,
            CascadeType.PERSIST,
            CascadeType.REFRESH
    })
    @JoinColumn(name = "to_task_template_id")
    protected TaskTemplate toTaskTemplate;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TaskTemplate2TaskTemplate that = (TaskTemplate2TaskTemplate) o;
        return Objects.equals(id, that.id) &&
                Objects.equals(processTemplate, that.processTemplate) &&
                Objects.equals(fromTaskTemplate, that.fromTaskTemplate) &&
                Objects.equals(toTaskTemplate, that.toTaskTemplate);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, processTemplate, fromTaskTemplate, toTaskTemplate);
    }

    @Override
    public String toString() {
        return "TaskTemplate2TaskTemplate{" +
                "id=" + id +
                ", processTemplate=" + processTemplate +
                ", fromTaskTemplate=" + fromTaskTemplate +
                ", toTaskTemplate=" + toTaskTemplate +
                '}';
    }

    public ProcessTemplate getProcessTemplate() {
        return processTemplate;
    }

    public void setProcessTemplate(ProcessTemplate processTemplate) {
        this.processTemplate = processTemplate;
    }

    public TaskTemplate getFromTaskTemplate() {
        return fromTaskTemplate;
    }

    public void setFromTaskTemplate(TaskTemplate fromTaskTemplate) {
        this.fromTaskTemplate = fromTaskTemplate;
    }

    public TaskTemplate getToTaskTemplate() {
        return toTaskTemplate;
    }

    public void setToTaskTemplate(TaskTemplate toTaskTemplate) {
        this.toTaskTemplate = toTaskTemplate;
    }
}
