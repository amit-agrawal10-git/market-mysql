package com.market.analytics.dao.repository;

import com.market.analytics.entity.Indices;
import com.market.analytics.entity.Stock;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

import java.math.BigInteger;

@RepositoryRestResource(path = "indices")
public interface IndicesRepository extends JpaRepository<Indices,BigInteger> {

}
