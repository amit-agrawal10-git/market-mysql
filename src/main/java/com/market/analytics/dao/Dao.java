package com.market.analytics.dao;

import com.market.analytics.entity.BaseObject;

import java.io.Serializable;
import java.util.List;

public interface Dao <T extends BaseObject, PK extends Serializable> {

    public List<T> getObjects(Class<T> clazz, int... maxRes);
    public void removeObject(Class<T> clazz, PK id);
    public void saveOrUpdate(T object);
    public void save(T object);
    public void commit();

}
