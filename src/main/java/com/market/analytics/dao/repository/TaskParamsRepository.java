package com.market.analytics.dao.repository;

import com.market.analytics.entity.metadata.TaskAttribute;
import com.market.analytics.entity.process.TaskTemplate2TaskTemplate;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

import java.math.BigInteger;

@RepositoryRestResource(path = "taskparams")
public interface TaskParamsRepository extends JpaRepository<TaskAttribute,BigInteger> {

}
