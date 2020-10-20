package com.market.analytics.entity.fno;

import com.market.analytics.entity.Indices;

import javax.persistence.*;
import java.math.BigInteger;
import java.util.Date;
import java.util.Objects;

@Entity
@DiscriminatorValue("FUTIDX")
public class FuturesIndexBhav extends FOBhav {

    public FuturesIndexBhav(){}
    @ManyToOne(cascade = {
            CascadeType.DETACH,
            CascadeType.MERGE,
            CascadeType.PERSIST,
            CascadeType.REFRESH
    })
    @JoinColumn
    private Indices indices;

    public FuturesIndexBhav(Date date, Date expiryDate, Double open, Double close, Double high, Double low, Double oi_change, BigInteger openInterest, Indices indices) {
        super(date, expiryDate, open, close, high, low, oi_change, openInterest);
        this.indices = indices;
    }

    @Override
    public String toString() {
        return "FuturesStockBhav{" +
                "indices=" + indices +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FuturesIndexBhav that = (FuturesIndexBhav) o;
        return Objects.equals(indices, that.indices);
    }

    @Override
    public int hashCode() {
        return Objects.hash(indices);
    }
}
