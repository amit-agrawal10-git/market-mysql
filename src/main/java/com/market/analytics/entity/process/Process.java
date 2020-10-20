package com.market.analytics.entity.process;


import com.market.analytics.entity.BaseObject;
import com.market.analytics.entity.metadata.ProcessType;

import javax.persistence.*;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.Objects;

@Entity
@Table(name = "process")
public class Process extends BaseObject implements Serializable {

    public Process(){}

    public Process(ProcessType type, ProcessStatus processStatus, ProcessTemplate processTemplate, Boolean enabled) {
        this.type = type;
        this.processStatus = processStatus;
        this.processTemplate = processTemplate;
        this.enabled = enabled;
    }

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    protected BigInteger id;

    @Column(unique = true)
    @Enumerated(EnumType.STRING)
    protected ProcessType type;

    @OneToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "process_status_id")
    protected ProcessStatus processStatus;

    @OneToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "process_template_id")
    protected ProcessTemplate processTemplate;

    public ProcessTemplate getProcessTemplate() {
        return processTemplate;
    }

    public void setProcessTemplate(ProcessTemplate processTemplate) {
        this.processTemplate = processTemplate;
    }

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    @Column
    protected Boolean enabled;

    public ProcessType getType() {
        return type;
    }

    public void setType(ProcessType type) {
        this.type = type;
    }

    public ProcessStatus getProcessStatus() {
        return processStatus;
    }

    public void setProcessStatus(ProcessStatus processStatus) {
        this.processStatus = processStatus;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Process process = (Process) o;
        return Objects.equals(id, process.id) &&
                type == process.type &&
                Objects.equals(processStatus, process.processStatus) &&
                Objects.equals(processTemplate, process.processTemplate) &&
                Objects.equals(enabled, process.enabled);
    }

    @Override
    public String toString() {
        return "Process{" +
                "id=" + id +
                ", type=" + type +
                ", processStatus=" + processStatus +
                ", processTemplate=" + processTemplate +
                ", enabled=" + enabled +
                '}';
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, type);
    }
}
