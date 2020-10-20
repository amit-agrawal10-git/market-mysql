package com.market.analytics.dao.impl;

import com.market.analytics.dao.StockDao;
import com.market.analytics.entity.Scrip;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import javax.persistence.EntityManager;
import javax.persistence.TypedQuery;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Path;
import javax.persistence.criteria.Root;
import java.util.List;

@Repository
public class StockDaoImpl extends BaseDaoImpl implements StockDao {

    @Autowired
    EntityManager entityManager;

    @Override
    public List getAllScripCodesByClass(Class<? extends Scrip> clazz) {
        CriteriaBuilder criteriaBuilder = entityManager.getCriteriaBuilder();
        CriteriaQuery criteriaQuery = criteriaBuilder.createQuery(clazz);
        Root from = criteriaQuery.from(clazz);
        Path<String> codePath = from.get("code");
        CriteriaQuery select = criteriaQuery.select(codePath);
        TypedQuery typedQuery = entityManager.createQuery(select);
        return typedQuery.getResultList().isEmpty()?null:typedQuery.getResultList();
    }
}
