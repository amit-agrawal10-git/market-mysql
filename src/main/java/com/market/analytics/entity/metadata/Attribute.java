package com.market.analytics.entity.metadata;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.market.analytics.entity.BaseObject;
import com.market.analytics.validation.annotation.DefaultValueFormatMatch;
import org.springframework.util.StringUtils;

import javax.persistence.*;
import java.io.Serializable;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Objects;

@Entity
@DefaultValueFormatMatch(typeFieldName = "type", defaultValueFieldName = "defaultValue")
public class Attribute extends BaseObject implements Serializable {

    public Attribute(){}
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    protected BigInteger id;

    @Column
    protected String name, defaultValue;

    @Column
    @Enumerated(EnumType.STRING)
    protected AttributeType type;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Object getDefaultValue() throws Exception {
        if(this.defaultValue==null|| StringUtils.isEmpty(this.defaultValue)){
            return "";
        }
        Object result = "";
        switch(type){
            case STRING:
                result = defaultValue;
                break;
            case NUMBER:
                result = new BigDecimal(defaultValue);
                break;
            case DATE:
                result = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss").parse(defaultValue);
                break;
            case BOOLEAN:
                result = new Boolean(defaultValue);
                break;
        }
        return result;
    }

    public void setDefaultValue(String defaultValue) {
        this.defaultValue = defaultValue;
    }

    @JsonIgnore
    public void setDefaultValue(Boolean value) {
        this.defaultValue = value.toString();
    }

    @JsonIgnore
    public void setDefaultValue(Date date) {
        this.defaultValue = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss").format(date);
    }

    @JsonIgnore
    public void setDefaultValue(BigDecimal bigDecimal) {
        this.defaultValue = bigDecimal.toString();
    }

    public AttributeType getType() {
        return type;
    }

    public void setType(AttributeType type) {
        this.type = type;
    }

    public Attribute(String name, AttributeType type) {
        this.name = name;
        this.type = type;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Attribute attribute = (Attribute) o;
        return Objects.equals(id, attribute.id) &&
                Objects.equals(name, attribute.name) &&
                Objects.equals(defaultValue, attribute.defaultValue) &&
                Objects.equals(type, attribute.type);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, name, defaultValue, type);
    }

    @Override
    public String toString() {
        return "Attribute{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", defaultValue='" + defaultValue + '\'' +
                ", type='" + type + '\'' +
                '}';
    }

    public BigInteger getId() {
        return id;
    }

    public void setId(BigInteger id) {
        this.id = id;
    }
}
