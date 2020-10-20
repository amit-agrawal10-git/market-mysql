package com.market.analytics.entity.fno;

import com.market.analytics.entity.Stock;

import javax.persistence.*;
import java.math.BigInteger;
import java.util.Date;
import java.util.Objects;

@Entity
@DiscriminatorValue("FUTSTK")
public class FuturesStockBhav extends FOBhav {

    public FuturesStockBhav(){}
    @ManyToOne(cascade = {
            CascadeType.DETACH,
            CascadeType.MERGE,
            CascadeType.PERSIST,
            CascadeType.REFRESH
    })
    @JoinColumn
    private Stock stock;

    public Stock getStock() {
        return stock;
    }

    public void setStock(Stock stock) {
        this.stock = stock;
    }

    public FuturesStockBhav(Date date, Date expiryDate, Double open, Double close, Double high, Double low, Double oi_change, BigInteger openInterest, Stock stock) {
        super(date, expiryDate, open, close, high, low, oi_change, openInterest);
        this.stock = stock;
    }

    @Override
    public String toString() {
        return "FuturesStockBhav{" +
                "stock=" + stock +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FuturesStockBhav that = (FuturesStockBhav) o;
        return Objects.equals(stock, that.stock);
    }

    @Override
    public int hashCode() {
        return Objects.hash(stock);
    }
}
