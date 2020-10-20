package com.market.analytics.entity.fno;

import com.market.analytics.entity.BaseObject;

import javax.persistence.*;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.Date;


@Entity
@Table(uniqueConstraints = {
        @UniqueConstraint(name = "uk_fobhav_stock_date" , columnNames={"strike_price","expiry_date","option_type", "stock_id","date"}),
        @UniqueConstraint(name = "uk_fobhav_indicies_date" , columnNames={"strike_price","expiry_date","option_type", "indices_id","date"})
        })
@Inheritance(strategy= InheritanceType.SINGLE_TABLE)
@DiscriminatorColumn(name="INSTRUMENT", discriminatorType= DiscriminatorType.STRING)
public abstract class FOBhav extends BaseObject implements Serializable {

    public  FOBhav(){}
    public FOBhav(Date date, Date expiryDate, Double open, Double close, Double high, Double low, Double oi_change, BigInteger openInterest) {
        this.date = date;
        this.expiryDate = expiryDate;
        this.open = open;
        this.close = close;
        this.high = high;
        this.low = low;
        this.oi_change = oi_change;
        this.openInterest = openInterest;
    }

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private BigInteger id;

    @Column
    private Date date;

    @Column(name = "expiry_date")
    private Date expiryDate;

    @Column
    private Double open, close, high, low;

    @Column
    private Double oi_change;

    @Column(name="open_interest")
    private BigInteger openInterest;

    public Date getDate() {
        return date;
    }

    public void setDate(Date date) {
        this.date = date;
    }

    public Date getExpiryDate() {
        return expiryDate;
    }

    public void setExpiryDate(Date expiryDate) {
        this.expiryDate = expiryDate;
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

    public Double getOi_change() {
        return oi_change;
    }

    public void setOi_change(Double oi_change) {
        this.oi_change = oi_change;
    }

    public BigInteger getOpenInterest() {
        return openInterest;
    }

    public void setOpenInterest(BigInteger openInterest) {
        this.openInterest = openInterest;
    }
}
