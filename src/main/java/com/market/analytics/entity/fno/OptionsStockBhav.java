package com.market.analytics.entity.fno;

import com.market.analytics.entity.Stock;

import javax.persistence.*;
import java.math.BigInteger;
import java.util.Date;
import java.util.Objects;

@Entity
@DiscriminatorValue("OPTSTK")
public class OptionsStockBhav extends FuturesStockBhav {

    public OptionsStockBhav(){}
    public OptionsStockBhav(Date date, Date expiryDate, Double open, Double close, Double high, Double low, Double oi_change, BigInteger openInterest, Stock stock, Double strikePrice, String optionType) {
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
        OptionsStockBhav that = (OptionsStockBhav) o;
        return Objects.equals(strikePrice, that.strikePrice) &&
                Objects.equals(optionType, that.optionType);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), strikePrice, optionType);
    }

    @Override
    public String toString() {
        return "OptionsStockBhav{" +
                "strikePrice=" + strikePrice +
                ", optionType='" + optionType + '\'' +
                '}';
    }
}
