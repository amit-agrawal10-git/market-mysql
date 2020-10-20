package com.market.analytics.dao.impl;

import com.market.analytics.dao.Dao;
import com.market.analytics.entity.BaseObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import javax.persistence.EntityManager;
import javax.persistence.TypedQuery;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Root;
import java.io.Serializable;
import java.util.List;

@Repository
public class BaseDaoImpl<T extends BaseObject, PK extends Serializable> implements Dao<T, PK>  {

    @Autowired
    EntityManager entityManager;

    @Override
    public List<T> getObjects(Class<T> clazz, int... maxResult) {
        CriteriaBuilder criteriaBuilder = entityManager.getCriteriaBuilder();
        CriteriaQuery<T> criteriaQuery = criteriaBuilder.createQuery(clazz);
        Root<T> from = criteriaQuery.from(clazz);
        CriteriaQuery<T> select = criteriaQuery.select(from);
        TypedQuery<T> typedQuery = entityManager.createQuery(select);
        if(maxResult != null && maxResult.length>0)
        return typedQuery.setMaxResults(maxResult[0]).getResultList();
        else
        return typedQuery.getResultList();
    }

    @Override
    public void removeObject(Class<T> clazz, PK id) {
        T t = entityManager.find(clazz,id);
        entityManager.remove(t);
    }

    @Override
    public void saveOrUpdate(T object) {
       object = entityManager.merge(object);
    }

    @Override
    public void save(T object) {
       entityManager.persist(object);
    }

    @Override
    public void commit() {
        entityManager.flush();
        entityManager.clear();
    }

}
