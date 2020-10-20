package com.market.analytics.service.impl;

import com.market.analytics.dao.Dao;
import com.market.analytics.entity.BaseObject;
import com.market.analytics.service.Manager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigInteger;
import java.util.List;

@Service
@Transactional
public class BaseManagerImpl<T extends BaseObject, PK extends BigInteger> implements Manager<T,PK> {

    @Autowired
    @Qualifier("baseDaoImpl")
    Dao dao;

    @Override
    public List<T> getObjects(Class<T> clazz, int... maxResult) {
        return dao.getObjects(clazz,maxResult);
    }

    @Override
    public void removeObject(Class<T> clazz, PK id) {
        dao.removeObject(clazz,id);
    }


    @Override
    public void saveOrUpdate(T object) {
        dao.saveOrUpdate(object);
    }

    @Override
    public void save(T object) {
        dao.save(object);
    }

    @Override
    public void commit() {
        dao.commit();
    }

}
