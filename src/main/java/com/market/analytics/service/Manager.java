package com.market.analytics.service;

import com.market.analytics.entity.BaseObject;
import org.springframework.data.jpa.repository.JpaRepository;

import java.io.Serializable;
import java.util.List;

public interface Manager<T extends BaseObject, PK extends Serializable> {

    public List<T> getObjects(Class<T> clazz, int... maxResults);
    public void removeObject(Class<T> clazz, PK id);
    public void saveOrUpdate(T object);
    public void save(T object);
    public void commit();

}
