package com.market.analytics.entity;


import javax.persistence.*;
import java.math.BigInteger;
import java.util.Date;
import java.util.Objects;

@Entity
@DiscriminatorValue("STOCK")
public class StockBhav extends Bhav {

    private static final long serialVersionUID = 4507697070438952884L;

    public StockBhav(){}

    public StockBhav(Date date, Double open, Double close, Double high, Double low, Double previousclose, Stock stock, Double totaltradedValue, BigInteger totaltradedqtty, BigInteger totaltrades) {
        super(date, open, close, high, low, previousclose);
        this.stock = stock;
        this.totaltradedValue = totaltradedValue;
        this.totaltradedqtty = totaltradedqtty;
        this.totaltrades = totaltrades;
    }

    @ManyToOne(cascade=CascadeType.ALL)
    @JoinColumn(name="stock_id")
    private Stock stock;

    @Column
    private Double totaltradedValue;

    @Column
    private BigInteger totaltradedqtty, totaltrades;

    public Stock getStock() {
        return stock;
    }

    public void setStock(Stock stock) {
        this.stock = stock;
    }

    public BigInteger getTotaltradedqtty() {
        return totaltradedqtty;
    }

    public void setTotaltradedqtty(BigInteger totaltradedqtty) {
        this.totaltradedqtty = totaltradedqtty;
    }

    public Double getTotaltradedValue() {
        return totaltradedValue;
    }

    public void setTotaltradedValue(Double totaltradedValue) {
        this.totaltradedValue = totaltradedValue;
    }

    public BigInteger getTotaltrades() {
        return totaltrades;
    }

    public void setTotaltrades(BigInteger totaltrades) {
        this.totaltrades = totaltrades;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        StockBhav stockBhav = (StockBhav) o;
        return Objects.equals(stock, stockBhav.stock) &&
                Objects.equals(totaltradedValue, stockBhav.totaltradedValue) &&
                Objects.equals(totaltradedqtty, stockBhav.totaltradedqtty) &&
                Objects.equals(totaltrades, stockBhav.totaltrades);
    }

    @Override
    public int hashCode() {
        return Objects.hash(stock, totaltradedValue, totaltradedqtty, totaltrades);
    }

    @Override
    public String toString() {
        return "StockBhav{" +
                "stock=" + stock +
                ", totaltradedValue=" + totaltradedValue +
                ", totaltradedqtty=" + totaltradedqtty +
                ", totaltrades=" + totaltrades +
                '}';
    }
}
