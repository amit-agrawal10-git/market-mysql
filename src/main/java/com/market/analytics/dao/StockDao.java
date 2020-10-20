package com.market.analytics.dao;

import com.market.analytics.entity.Scrip;

import java.util.List;

public interface StockDao extends Dao {

    List<String> getAllScripCodesByClass(Class<? extends Scrip> aClass);

}
