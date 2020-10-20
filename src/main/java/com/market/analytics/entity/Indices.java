package com.market.analytics.entity;


import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;

@Entity
@DiscriminatorValue("INDEX")
public class Indices extends Scrip {

    public Indices(){}
    public Indices(String code, String name) {
        super(code, name);
    }
}

