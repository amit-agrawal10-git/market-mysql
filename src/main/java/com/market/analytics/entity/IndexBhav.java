package com.market.analytics.entity;


import javax.persistence.*;
import java.math.BigInteger;
import java.util.Objects;

@Entity
@DiscriminatorValue("INDEX")
public class IndexBhav extends Bhav {

    private static final long serialVersionUID = -4624986881470805508L;

    public IndexBhav(){}
    public IndexBhav(Indices indices, Double PE, Double PB, BigInteger totaltradedvolume) {
        this.indices = indices;
        this.PE = PE;
        this.PB = PB;
        this.totaltradedvolume = totaltradedvolume;
    }

    @ManyToOne(cascade=CascadeType.ALL)
    @JoinColumn(name="indices_id")
    private Indices indices;

    @Column
    private Double PE, PB;

    @Column
    private BigInteger totaltradedvolume;

    public Double getPE() {
        return PE;
    }

    public void setPE(Double PE) {
        this.PE = PE;
    }

    public Double getPB() {
        return PB;
    }

    public void setPB(Double PB) {
        this.PB = PB;
    }

    public BigInteger getTotaltradedvolume() {
        return totaltradedvolume;
    }

    public void setTotaltradedvolume(BigInteger totaltradedvolume) {
        this.totaltradedvolume = totaltradedvolume;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        IndexBhav indexBhav = (IndexBhav) o;
        return Objects.equals(indices, indexBhav.indices) &&
                Objects.equals(PE, indexBhav.PE) &&
                Objects.equals(PB, indexBhav.PB) &&
                Objects.equals(totaltradedvolume, indexBhav.totaltradedvolume);
    }

    @Override
    public int hashCode() {
        return Objects.hash(indices, PE, PB, totaltradedvolume);
    }

    @Override
    public String toString() {
        return "IndexBhav{" +
                "indices=" + indices +
                ", PE=" + PE +
                ", PB=" + PB +
                ", totaltradedvolume=" + totaltradedvolume +
                '}';
    }
}
