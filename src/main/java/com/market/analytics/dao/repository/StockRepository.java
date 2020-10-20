package com.market.analytics.dao.repository;

import com.market.analytics.entity.Stock;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

import java.math.BigInteger;

@RepositoryRestResource(path = "stocks")
public interface StockRepository extends JpaRepository<Stock,BigInteger> {

}
