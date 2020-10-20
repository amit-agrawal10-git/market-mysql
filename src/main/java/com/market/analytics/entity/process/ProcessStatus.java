package com.market.analytics.entity.process;


import com.market.analytics.entity.BaseObject;
import com.market.analytics.entity.metadata.ProcessType;

import javax.persistence.*;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.Date;
import java.util.Objects;

@Entity
@Table(name = "process_status")
public class ProcessStatus extends BaseObject implements Serializable {

    public ProcessStatus() {
    }

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    protected BigInteger id;

    @Column(unique = true)
    @Enumerated(EnumType.STRING)
    protected ProcessType type;

    @Column(nullable = false)
    protected Date startDate;

    @Column(nullable = true)
    protected Date executedupto;

    public ProcessStatus(ProcessType type, Date startDate, Date executedupto) {
        this.type = type;
        this.startDate = startDate;
        this.executedupto = executedupto;
    }

    public ProcessType getType() {
        return type;
    }

    public void setType(ProcessType type) {
        this.type = type;
    }

    public Date getStartDate() {
        return startDate;
    }

    public void setStartDate(Date startDate) {
        this.startDate = startDate;
    }

    public Date getExecutedupto() {
        return executedupto;
    }

    public void setExecutedupto(Date executedupto) {
        this.executedupto = executedupto;
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, type, startDate, executedupto);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ProcessStatus that = (ProcessStatus) o;
        return Objects.equals(id, that.id) &&
                getType() == that.getType() &&
                Objects.equals(getStartDate(), that.getStartDate()) &&
                Objects.equals(getExecutedupto(), that.getExecutedupto());
    }

    @Override
    public String toString() {
        return "ProcessStatus{" +
                "id=" + id +
                ", type=" + type +
                ", startDate=" + startDate +
                ", executedupto=" + executedupto +
                '}';
    }
}
