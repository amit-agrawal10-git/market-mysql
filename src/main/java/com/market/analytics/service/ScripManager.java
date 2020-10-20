package com.market.analytics.service;

import com.market.analytics.entity.Scrip;
import com.market.analytics.entity.Stock;

import java.util.List;

public interface ScripManager {
    List<String> getAllScripCodesByClass(Class<? extends Scrip> aClass);
    public List<Stock> getAllStocks();

}
