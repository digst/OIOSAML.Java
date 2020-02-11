package dk.itst.oiosaml.idp.config;

import dk.itst.oiosaml.idp.dao.model.enums.AttributeProfile;
import dk.itst.oiosaml.idp.dao.model.enums.LevelOfAssurance;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Session {

    private String username;

    private String password;

    private AttributeProfile attributeProfile;

    private LevelOfAssurance levelOfAssurance;

    private boolean addRequiredAttributes;

    private boolean correctNameID;
}
