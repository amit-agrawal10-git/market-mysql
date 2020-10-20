package com.market.analytics.entity;


import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;

@Entity
@DiscriminatorValue("STOCK")
public class Stock extends Scrip {

    public Stock(String code, String name) {
        super(code, name);
    }

    public Stock(){}
}

