package dk.gov.oio.saml.oiobpp;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.annotation.XmlElementDecl;
import javax.xml.bind.annotation.XmlRegistry;
import javax.xml.namespace.QName;

@XmlRegistry
public class ObjectFactory {
    private final static QName _PrivilegeList_QNAME = new QName("http://digst.dk/oiosaml/basic_privilege_profile", "PrivilegeList");

    public PrivilegeList createPrivilegeList() {
        return new PrivilegeList();
    }

    public Constraint createConstraint() {
        return new Constraint();
    }

    public PrivilegeGroup createPrivilegeGroup() {
        return new PrivilegeGroup();
    }

    @XmlElementDecl(namespace = "http://digst.dk/oiosaml/basic_privilege_profile", name = "PrivilegeList")
    public JAXBElement<PrivilegeList> createPrivilegeList(PrivilegeList value) {
        return new JAXBElement<PrivilegeList>(_PrivilegeList_QNAME, PrivilegeList.class, null, value);
    }
}
