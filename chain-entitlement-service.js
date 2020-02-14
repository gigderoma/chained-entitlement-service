importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importClass(Packages.com.tivoli.am.fim.fedmgr2.trust.util.LocalSTSClient);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.STSUniversalUser);



function getAttrsContainer(searchDN, chain) {

    var result = null;
    var req_stsuu = new STSUniversalUser();

    req_stsuu.addAttribute(new com.tivoli.am.fim.trustserver.sts.uuser.Attribute("searchDN", "urn:ibm:temp:attr", searchDN));
    IDMappingExtUtils.traceString("Sending STSUU as base token: " + req_stsuu);

    // wrap in an XML object ready for exchange
    var StsuuXML = req_stsuu.toXML().getDocumentElement();

    // exchange for STSUU		
    var res = LocalSTSClient.doRequest(
        "http://schemas.xmlsoap.org/ws/2005/02/trust/Validate",
        "http://appliesto/" + chain + "/stsuu",
        "http://issuer/" + chain + "/stsuu",
        StsuuXML,
        null);

    if (res.errorMessage == null) {

        var rsp_stsuu = new STSUniversalUser();
        rsp_stsuu.fromXML(res.token);
        IDMappingExtUtils.traceString("got result: " + rsp_stsuu.toString());

        result = rsp_stsuu.getAttributeContainer();


    } else {
        IDMappingExtUtils.throwSTSException("An error occurred invoking the STS: " + res.errorMessage);

        // abort the authentication in case it is not possible to get data
        success.setValue(false);
    }
    return result;
}




// Get the managerDN and other user's registry attribute from session context , they have been added by the username and password auth mechanism during initial login verification 
var managerDN = context.get(Scope.SESSION, "urn:ibm:security:authentication:asf:mechanism:password", "managerDN");
var userEmailAddress = context.get(Scope.SESSION, "urn:ibm:security:authentication:asf:mechanism:password", "emailAddress");
var userPagerNumber = context.get(Scope.SESSION, "urn:ibm:security:authentication:asf:mechanism:password", "pagerNumber");

// Get the manager data from first STS Chain 
var tempAttrCont = getAttrsContainer(managerDN, "chain-1");
var managerTelephone = tempAttrCont.getAttributeValueByNameAndType("managerTelephone", "urn:ibm:names:ITFIM:5.1:accessmanager");
var managerEmail = tempAttrCont.getAttributeValueByNameAndType("managerEmail", "urn:ibm:names:ITFIM:5.1:accessmanager");
var secretaryDN = tempAttrCont.getAttributeValueByNameAndType("secretaryDN", "urn:ibm:names:ITFIM:5.1:accessmanager");

// Get the secretary  data from second STS Chain 
tempAttrCont = getAttrsContainer(secretaryDN, "chain-2");
var secretaryFax = tempAttrCont.getAttributeValueByNameAndType("secretaryFax", "urn:ibm:names:ITFIM:5.1:accessmanager");



// add all the retrieved attributes into the  session context as they will be automatically added in the user credential
context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "tagvalue_aac_emailAddress", userEmailAddress[0]);
context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "tagvalue_aac_pagerNumber", userPagerNumber[0]);
context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "tagvalue_aac_managerDN", managerDN[0]);

context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "tagvalue_aac_managerTelephone", managerTelephone);
context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "tagvalue_aac_managerEmail", managerEmail);
context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "tagvalue_aac_secretaryDN", secretaryDN);
context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "tagvalue_aac_secretaryFax", secretaryFax);

context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "authenticatedBy", "IBM Security Access Manager AAC Runtime");


success.setValue(true);
