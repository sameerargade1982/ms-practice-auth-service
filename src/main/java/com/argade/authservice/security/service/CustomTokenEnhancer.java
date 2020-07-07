package com.argade.authservice.security.service;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
//import com.unityhealth.connect.XMLApiBean;

//import static org.apache.commons.lang3.RandomStringUtils.randomAlphabetic;

/**
 * Created by shanefox on 24/10/2016.
 */
public class CustomTokenEnhancer implements TokenEnhancer {

    private static final Logger log = LoggerFactory.getLogger(CustomTokenEnhancer.class);

    @Override
    public OAuth2AccessToken enhance (OAuth2AccessToken accessToken,
                                      OAuth2Authentication authentication) {

        UserDetailsImpl user = (UserDetailsImpl) authentication.getPrincipal();
        log.debug("username: {}", user.getUsername());

//        Map<String, Object> additionalInfo = new HashMap<>();
//        if(user.getAccount()!= null) {
//            additionalInfo.put("groupIds", getGroupIds(user.getAccount().getGroups()));
//            
//            additionalInfo.put("sherpaOptIn", user.getAccount().getSherpaOptIn());
//            
//            if (user.getAccount().getUserType().equals("store_manager") || user.getAccount().getUserType().equals("store_owner")) {
//                additionalInfo.put("managerAccess", true);
//            } else {
//                additionalInfo.put("managerAccess", false);
//            }
//            
//            additionalInfo.put("user_ID", user.getAccount().getId());
//            
//            
//            
//        }else{
//          Integer[]groupIds = {4};
//            additionalInfo.put("groupIds", groupIds );
//            
//            additionalInfo.put("sherpaOptIn", user.getCompanyUsers().getSherpaOptIn());
//            
//             if (user.getAccount().getUserType().equals("store_manager") || user.getAccount().getUserType().equals("store_owner")) {
//                additionalInfo.put("managerAccess", true);
//            } else {
//                additionalInfo.put("managerAccess", false);
//            }
//        }
//        
//        try{
////            System.out.println("The name of the user " + user.getPassword() );
////             XMLApiBean breeze = new XMLApiBean("http://connect.itherapeutics.com.au", user.getUsername(), "password", null);
////        String breezeSession = breeze.getBreezesession();
////         System.out.println("The value of the user breezeSession " + breezeSession );
////additionalInfo.put("breezesession", breezeSession);
//        }catch(Exception e){
//            e.printStackTrace();
//        }
       

       // ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInfo);
        return accessToken;
    }

//    private Integer[] getGroupIds(List<Group> groups) {
//        ArrayList<Integer> groupIds = new ArrayList<>(groups.size());
//
//        for (Group group : groups) {
//            groupIds.add(group.getId());
//        }
//
//        return groupIds.toArray(new Integer[groupIds.size()]);
//    }

}
