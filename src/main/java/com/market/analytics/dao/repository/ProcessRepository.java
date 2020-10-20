package com.market.analytics.dao.repository;

import com.market.analytics.entity.Indices;
import com.market.analytics.entity.process.Process;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

import java.math.BigInteger;

@RepositoryRestResource(path = "processes")
public interface ProcessRepository extends JpaRepository<Process,BigInteger> {

}
