package com.market.analytics.dao.repository;

import com.market.analytics.entity.metadata.ProcessTaskAttribute;
import com.market.analytics.entity.metadata.TaskAttribute;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

import java.math.BigInteger;

@RepositoryRestResource(path = "processtaskparams")
public interface ProcessTaskParamsRepository extends JpaRepository<ProcessTaskAttribute,BigInteger> {

}
