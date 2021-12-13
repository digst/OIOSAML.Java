package dk.gov.oio.saml.oiobpp;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = { "privilege", "constraint" })
public class PrivilegeGroup implements Serializable {
    private static final long serialVersionUID = -1219061603751347359L;

    @XmlElement(name = "Privilege", required = true)
    protected List<String> privilege;
    
    @XmlElement(name = "Constraint", required = false)
    protected List<Constraint> constraint;

    @XmlAttribute(name = "Scope")
    protected String scope;

    public List<String> getPrivilege() {
        return privilege;
    }
    
    public void setPrivilege(List<String> privilege) {
        this.privilege = privilege;
    }
    
    public List<Constraint> getConstraint() {
        if (this.constraint == null) {
            return new ArrayList<Constraint>();
        }
        
        return constraint;
    }

    public void setConstraint(List<Constraint> constraint) {
        this.constraint = constraint;
    }
    
    public String getScope() {
        return scope;
    }
    
    public void setScope(String scope) {
        this.scope = scope;
    }
}
