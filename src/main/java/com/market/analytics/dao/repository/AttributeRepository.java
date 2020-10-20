package com.market.analytics.dao.repository;

import com.market.analytics.entity.metadata.Attribute;
import com.market.analytics.entity.process.Process;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

import java.math.BigInteger;

@RepositoryRestResource(path = "params")
public interface AttributeRepository extends JpaRepository<Attribute,BigInteger> {

}
