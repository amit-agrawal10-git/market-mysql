package com.market.analytics.validation.annotation;

import com.market.analytics.validation.validator.DefaultValueFormatMatchValidator;

import javax.validation.Constraint;
import javax.validation.Payload;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.TYPE, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = DefaultValueFormatMatchValidator.class)
public @interface DefaultValueFormatMatch {
    String message() default "{validator.defaultvalueformat.match.message}";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
    String typeFieldName();
    String defaultValueFieldName();
    String dateValueFormat() default "{validator.defaultvalueformat.match.dateValueFormat}";
}
