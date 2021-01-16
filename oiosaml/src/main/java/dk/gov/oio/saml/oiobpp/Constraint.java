package dk.gov.oio.saml.oiobpp;

import java.io.Serializable;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.XmlValue;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "Constraint", propOrder = { "value" })
public class Constraint implements Serializable {
	private static final long serialVersionUID = -9146150254468938758L;

	@XmlValue
    protected String value;

    @XmlAttribute(name = "Name", required = true)
    @XmlSchemaType(name = "anyURI")
    protected String name;

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public String getName() {
        return name;
    }

    public void setName(String value) {
        this.name = value;
    }
}