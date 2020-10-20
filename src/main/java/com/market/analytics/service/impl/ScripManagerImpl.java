package com.market.analytics.service.impl;

import com.market.analytics.dao.StockDao;
import com.market.analytics.dao.repository.StockRepository;
import com.market.analytics.entity.Scrip;
import com.market.analytics.entity.Stock;
import com.market.analytics.service.ScripManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional
public class ScripManagerImpl implements ScripManager {

    @Autowired
    private StockDao stockDao;

    @Override
    public List<String> getAllScripCodesByClass(Class<? extends Scrip> aClass) {
        return stockDao.getAllScripCodesByClass(aClass);
    }

    public List<Stock> getAllStocks() {
        return stockDao.getObjects(Stock.class);
    }
}
