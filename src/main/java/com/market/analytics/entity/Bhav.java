package com.market.analytics.entity;

import javax.persistence.*;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.Date;

@Entity
@Table(name="bhav",uniqueConstraints = {
        @UniqueConstraint(name = "uk_bhav_stock_date" , columnNames={"stock_id","date"}),
        @UniqueConstraint(name = "uk_bhav_indicies_date" , columnNames={"stock_id", "indices_id","date"})
        })
@Inheritance(strategy= InheritanceType.SINGLE_TABLE)
@DiscriminatorColumn(name="TYPE", discriminatorType= DiscriminatorType.STRING)
public abstract class Bhav extends BaseObject implements Serializable {

    public Bhav(){}

    public Bhav(Date date, Double open, Double close, Double high, Double low, Double previousclose) {
        this.date = date;
        this.open = open;
        this.close = close;
        this.high = high;
        this.low = low;
        this.previousclose = previousclose;
    }

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    protected BigInteger id;

    @Column
    protected Date date;

    @Column
    protected Double open, close, high, low, previousclose;

    public Date getDate() {
        return date;
    }

    public void setDate(Date date) {
        this.date = date;
    }

    public Double getOpen() {
        return open;
    }

    public void setOpen(Double open) {
        this.open = open;
    }

    public Double getClose() {
        return close;
    }

    public void setClose(Double close) {
        this.close = close;
    }

    public Double getHigh() {
        return high;
    }

    public void setHigh(Double high) {
        this.high = high;
    }

    public Double getLow() {
        return low;
    }

    public void setLow(Double low) {
        this.low = low;
    }

    public Double getPreviousclose() {
        return previousclose;
    }

    public void setPreviousclose(Double previousclose) {
        this.previousclose = previousclose;
    }
}
