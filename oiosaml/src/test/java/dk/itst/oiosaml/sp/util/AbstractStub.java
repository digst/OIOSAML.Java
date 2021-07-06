package dk.itst.oiosaml.sp.util;

import java.util.List;
import java.util.Set;

import javax.xml.namespace.QName;

import org.opensaml.common.SAMLObject;
import org.opensaml.xml.Namespace;
import org.opensaml.xml.NamespaceManager;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.util.IDIndex;
import org.opensaml.xml.validation.ValidationException;
import org.opensaml.xml.validation.Validator;
import org.opensaml.xml.schema.XSBooleanValue;
import org.w3c.dom.Element;

public class AbstractStub implements SAMLObject {

	public void deregisterValidator(Validator arg0) {
	}

	public List<Validator> getValidators() {
		return null;
	}

	public void registerValidator(Validator arg0) {
	}

	public void validate(boolean arg0) throws ValidationException {
	}

	public void addNamespace(Namespace arg0) {
	}

	public void detach() {
	}

	public Element getDOM() {
		return null;
	}

	public QName getElementQName() {
		return null;
	}

	public IDIndex getIDIndex() {
		return null;
	}

	public Set<Namespace> getNamespaces() {
		return null;
	}

	public String getNoNamespaceSchemaLocation() {
		return null;
	}

	public List<XMLObject> getOrderedChildren() {
		return null;
	}

	public XMLObject getParent() {
		return null;
	}

	public String getSchemaLocation() {
		return null;
	}

	public QName getSchemaType() {
		return null;
	}

	public boolean hasChildren() {
		return false;
	}

	public boolean hasParent() {
		return false;
	}

	public void releaseChildrenDOM(boolean arg0) {
	}

	public void releaseDOM() {
	}

	public void releaseParentDOM(boolean arg0) {
	}

	public void removeNamespace(Namespace arg0) {
	}

	public XMLObject resolveID(String arg0) {
		return null;
	}

	public XMLObject resolveIDFromRoot(String arg0) {
		return null;
	}

	public void setDOM(Element arg0) {
	}

	public void setNoNamespaceSchemaLocation(String arg0) {
	}

	public void setParent(XMLObject arg0) {
	}

	public void setSchemaLocation(String arg0) {
	}

    public NamespaceManager getNamespaceManager() {
        // TODO Auto-generated method stub
        return null;
    }

    public Boolean isNil() {
        // TODO Auto-generated method stub
        return null;
    }

    public XSBooleanValue isNilXSBoolean() {
        // TODO Auto-generated method stub
        return null;
    }

    public void setNil(Boolean arg0) {
        // TODO Auto-generated method stub
       
    }

    public void setNil(XSBooleanValue arg0) {
        // TODO Auto-generated method stub
       
    }
}
