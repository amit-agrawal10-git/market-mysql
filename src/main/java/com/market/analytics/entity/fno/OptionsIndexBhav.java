package com.market.analytics.entity.fno;

import com.market.analytics.entity.Indices;

import javax.persistence.Column;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import java.math.BigInteger;
import java.util.Date;
import java.util.Objects;

@Entity
@DiscriminatorValue("OPTIDX")
public class OptionsIndexBhav extends FuturesIndexBhav {

    public OptionsIndexBhav(){}
    public OptionsIndexBhav(Date date, Date expiryDate, Double open, Double close, Double high, Double low, Double oi_change, BigInteger openInterest, Indices stock, Double strikePrice, String optionType) {
        super(date, expiryDate, open, close, high, low, oi_change, openInterest, stock);
        this.strikePrice = strikePrice;
        this.optionType = optionType;
    }

    @Column(name = "strike_price")
    private Double strikePrice;

    @Column(name="option_type")
    private String optionType;


    public Double getStrikePrice() {
        return strikePrice;
    }

    public void setStrikePrice(Double strikePrice) {
        this.strikePrice = strikePrice;
    }

    public String getOptionType() {
        return optionType;
    }

    public void setOptionType(String optionType) {
        this.optionType = optionType;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        OptionsIndexBhav that = (OptionsIndexBhav) o;
        return Objects.equals(strikePrice, that.strikePrice) &&
                Objects.equals(optionType, that.optionType);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), strikePrice, optionType);
    }

    @Override
    public String toString() {
        return "OptionsIndexBhav{" +
                "strikePrice=" + strikePrice +
                ", optionType='" + optionType + '\'' +
                '}';
    }
}
