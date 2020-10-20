package com.market.analytics.validation.validator;

import com.market.analytics.entity.metadata.AttributeType;
import com.market.analytics.utility.Utils;
import com.market.analytics.validation.annotation.DefaultValueFormatMatch;
import org.apache.commons.beanutils.BeanUtils;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import java.math.BigDecimal;
import java.text.ParseException;

public class DefaultValueFormatMatchValidator implements ConstraintValidator<DefaultValueFormatMatch, Object> {

    private String typeFieldName;
    private String defaultValueFieldName;
    private String dateValueFormat;

    @Override
    public void initialize(final DefaultValueFormatMatch constraintAnnotation)
    {
        typeFieldName = constraintAnnotation.typeFieldName();
        defaultValueFieldName = constraintAnnotation.defaultValueFieldName();
        dateValueFormat = constraintAnnotation.dateValueFormat();
    }
    @Override
    public boolean isValid(final Object object, final ConstraintValidatorContext context)
    {
        try
        {
            Object type = BeanUtils.getProperty(object,typeFieldName);
            Object defaultValue = BeanUtils.getProperty(object, defaultValueFieldName);

            if(defaultValue == null)
                return true;

            if(type == null)
                return false;

            switch ((AttributeType)type){
                case BOOLEAN:
                    return "true".equals(defaultValue) || "false".equals(defaultValue);
                case DATE:
                    try{
                        Utils.parseDate(defaultValue.toString(), dateValueFormat);
                    } catch (ParseException e){
                        return false;
                    }
                case NUMBER:
                    try{
                        new BigDecimal(defaultValue.toString());
                    } catch (Exception e){
                        return false;
                    }
            }
            return true;
        }
        catch (final Exception ignore)
        {
            // ignore
        }
        return true;
    }

}
