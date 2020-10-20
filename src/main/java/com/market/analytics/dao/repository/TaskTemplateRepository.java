package com.market.analytics.dao.repository;

import com.market.analytics.entity.process.TaskTemplate2TaskTemplate;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

import java.math.BigInteger;

@RepositoryRestResource(path = "tasktemplates")
public interface TaskTemplateRepository extends JpaRepository<TaskTemplate2TaskTemplate,BigInteger> {

}
