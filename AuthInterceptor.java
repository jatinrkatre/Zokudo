package com.cards.auth.config;

import com.cards.auth.dto.UserDetailDTO;
import com.cards.auth.entities.ActivityLogs;
import com.cards.auth.enums.Status;
import com.cards.auth.exceptions.BizException;
import com.cards.auth.exceptions.ForbiddenException;
import com.cards.auth.exceptions.UnAuthorizedException;
import com.cards.auth.repositories.ActivityLogsRepository;
import com.cards.auth.security.JwtTokenUtil;
import com.cards.auth.util.*;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Splitter;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.client.Client;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@Slf4j
@Component
public class AuthInterceptor extends HandlerInterceptorAdapter {

    private final UrlMetaData urlMetaData;
    private final Client client;
    private final String applicationLevelUserName;
    private final String applicationLevelUserNameNew;
    private final String applicationLevelUserPassword;
    private final String applicationLevelUserPasswordNew;
    private final ActivityLogsRepository activityLogsRepository;
    private final String profile;
    private static final int TOKEN_EXPIRY_DURATION_IN_SECONDS = 30 * 60;
    private static final String USER_TOKEN_GENERATION_DATE_TIME_STAMP_SUFFIX = "_tokenGenerationDateTimeStamp";
    private final HashMap<String, String> TOKEN_MAP = new HashMap<>();
    private static final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS512;
    private final String secretKey;
    private final String ZOKUDO_MOBILE_APP_USER_PROGRAM_URL = "appuser";
    private final String AUTHORIZATION_TOKEN_PREFIX = "Bearer ";

    @Autowired
    public AuthInterceptor(final UrlMetaData urlMetaData,
                           @Qualifier(value = "client") final Client client,
                           @Value("${applicationLevel.user.name}") String applicationLevelUserName,
                           @Value("${applicationLevel.user.password}") String applicationLevelUserPassword,
                           @Value("${applicationLevel.user.name_new}") String applicationLevelUserNameNew,
                           @Value("${applicationLevel.user.password_new}") String applicationLevelUserPasswordNew,
                           @Value("${spring.profiles.active}") String profile,
                           final ActivityLogsRepository activityLogsRepository,
                           @Value("${spring.security.user.password}") final String secretKey
                           ) {
        this.urlMetaData = urlMetaData;
        this.client = client;
        this.applicationLevelUserName = applicationLevelUserName;
        this.applicationLevelUserNameNew = applicationLevelUserNameNew;
        this.applicationLevelUserPassword = applicationLevelUserPassword;
        this.applicationLevelUserPasswordNew = applicationLevelUserPasswordNew;
        this.activityLogsRepository = activityLogsRepository;
        this.profile = profile;
        this.secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());

    }


    @Override
    public boolean preHandle(final HttpServletRequest request, final HttpServletResponse response, final Object handler) {

        String programUrl = request.getHeader("program_url");
        String ipaddress = request.getHeader("ipaddress");
        String authorizationHeader = request.getHeader("Authorization");
        String userName;

        validateProgramUrl(programUrl,request,ipaddress);
        validateAuthorizationHeader(authorizationHeader,"NA", programUrl, request, ipaddress);


            if (StringUtils.isBlank(ipaddress)) {
                ipaddress = request.getHeader("X-FORWARDED-FOR");
                if (ipaddress == null || "".equals(ipaddress)) {
                    ipaddress = request.getRemoteAddr();
                }
            }
            if(programUrl.equalsIgnoreCase(ZOKUDO_MOBILE_APP_USER_PROGRAM_URL) && authorizationHeader.contains("Basic")){

                final String[] tokenSecrete = getUserNamePassword(authorizationHeader);
                verifyIfCredentialsMissing(request, programUrl, ipaddress, authorizationHeader, tokenSecrete);
                userName = tokenSecrete[0];

            }else {
                JwtTokenUtil.validateJwtToken(authorizationHeader);
                userName = parseUsernameFromJwt(authorizationHeader);
            }
            if(validateAppUser(userName)){
                log.info("Username is recognised as internal.");
                return true;
            }

            /*if (!validateAppUser(userName) && !checkWhiteListedIPAddress(ipaddress, programUrl, userName))
                throw new UnAuthorizedException("unauthorized ip address: " + ipaddress);*/

        String requestUrl = request.getHeader("request_url");
        if (requestUrl == null) {
            String error = "request url missing..Request";
            log.error(error);
            logActivity(true, error, userName, programUrl, request, ipaddress);
            throw new BizException("unauthorized request url");
        }
        fetchDataFromProductService(userName, programUrl, requestUrl, request, userName, ipaddress);

        logActivity(false, "", userName, programUrl, request, ipaddress);
        return true;
    }

    private void validateJwtToken(String authorizationHeader) {

        final List<String> tokens = Splitter.on(" ").trimResults().omitEmptyStrings().splitToList(authorizationHeader);
        if (tokens.size() != 2) {
            log.error("Authorization token must be in form of 'Bearer xxx...'");
            throw new BizException("Invalid authorization token");
        }
        if (!tokens.get(0).equals("Bearer")) {
            log.error("Authorization token doesn't starts with Bearer");
            throw new BizException("Invalid JWT authorization token");
        }
    }

    private void verifyIfCredentialsMissing(HttpServletRequest request, String programUrl, String ipaddress, String authorizationHeader, CharSequence[] tokenSecrete) {
        if (tokenSecrete.length != 2) {
            String error = "Either Username or Password is Missing";
            log.error(error);
            logActivity(true, error, getUserNamePassword(authorizationHeader)[0], programUrl, request, ipaddress);
            throw new BizException("Username and password is mandatory!");
        }
    }

    private void validateAuthorizationHeader(String authorizationHeader, String username, String programUrl, HttpServletRequest request, String ipaddress) {
        if (StringUtils.isEmpty(authorizationHeader)) {
            String error = "Authorization header missing or empty...";
            log.error(error);
            logActivity(true, error, username, programUrl, request, ipaddress);
            throw new BizException("Unauthorized access!");
        }
    }

    private void validateProgramUrl(String programUrl,HttpServletRequest request,String ipaddress) {
        if(StringUtils.isEmpty(programUrl)){
            String error = "program request url missing...";
            log.error(error);
            logActivity(true, error, "NA", programUrl, request, ipaddress);
            throw new BizException("unauthorized program url! please check request url");
        }
    }

    private String[] getUserNamePassword(String authorizationHeader) {
        if (StringUtils.isEmpty(authorizationHeader)) {
            throw new BizException("Unauthorized access!");
        }
        return (new String(Base64.getDecoder().decode((authorizationHeader.replaceAll("Basic ", ""))))).split(":");

    }

    private void logActivity(boolean error, String errorMessage, String username, String programUrl, HttpServletRequest request, String remoteAddr) {
        if (!applicationLevelUserName.equalsIgnoreCase(username)) {
            ActivityLogs activityLogs = new ActivityLogs();
            activityLogs.setSourceIp(remoteAddr);
            activityLogs.setProgram(programUrl);
            activityLogs.setError(error);
            activityLogs.setErrorMessage(errorMessage);
            activityLogs.setUserName(username);
            activityLogs.setUrl(request.getHeader("request_url"));
            String authorization = request.getHeader("authorization").length() > 240 ? request.getHeader("authorization").substring(0,240):request.getHeader("authorization");
            activityLogs.setAuthorization(
                    "authorization:" + authorization
            );
            activityLogsRepository.save(activityLogs);
        }
    }

    private boolean checkWhiteListedIPAddress(String ipAddress, String programUrl, String username) {
        if (!Constants.prod_profile.equals(profile))
            return true;

        return getDetailsByIPAddress(ipAddress, programUrl, username);
    }

    private boolean validateInternalAPICall(String[] tokenSecrete) {
        if (applicationLevelUserName.equals(tokenSecrete[0])
                && applicationLevelUserPassword.equals(tokenSecrete[1]))
            return true;
        return false;
    }

    private boolean getDetailsByIPAddress(String ipAddress, String programUrl, String username) {
        try {
            final MultivaluedMap<String, Object> headerMap = new MultivaluedHashMap<>();
            headerMap.add("accept", MediaType.APPLICATION_JSON_VALUE);
            String str = urlMetaData.GET_IP_DETAILS.replaceAll(Constants.urlEscapeConstant, programUrl);
            Response clientResponse = client.target(str + "/" + ipAddress)
                    .request()
                    .headers(headerMap)
                    .get();
            if (clientResponse.getStatus() != 200)
                return false;

            JSONObject jsonObject = new JSONObject(clientResponse.readEntity(String.class));

            jsonObject = jsonObject.getJSONObject("body");

            log.info("email : {} : {}", jsonObject.getString("userEmail") , username);
            log.info("compare :{}", username.equals(jsonObject.getString("userEmail")));

            if (!(username.equals(jsonObject.getString("userEmail"))))
                return false;

            log.info("status : {}", Status.active.getValue());
            log.info("json status : {}", jsonObject.getString("status"));
            log.info("return status :{}", Status.active.getValue().equalsIgnoreCase(jsonObject.getString("status")));

            return Status.active.getValue().equalsIgnoreCase(jsonObject.getString("status"));

        } catch (JSONException e) {
            log.error("Exception occurred", e);
            return false;
        }
    }

    private void fetchDataFromProductService(String userName, String programUrl, String requestUrl, HttpServletRequest request, String username, String ipAddress) {
        try {
            final MultivaluedMap<String, Object> headerMap = new MultivaluedHashMap<>();
            headerMap.add("username", userName);
            headerMap.add("program_url", programUrl);
            headerMap.add("accept", MediaType.APPLICATION_JSON_VALUE);
            String str = urlMetaData.AUTHENTICATE_AND_AUTHORIZE_USER.replaceAll(Constants.urlEscapeConstant, programUrl);
            Response clientResponse = client.target(str)
                    .request()
                    .headers(headerMap)
                    .get();
            if (clientResponse.getStatus() != 200) {
                logActivity(true, "invalid request!program details not found", username, programUrl, request, ipAddress);
                throw new BizException("invalid request!program details not found");
            }
            //String clientResponseStr = AESDecryption.decrypt(clientResponse.readEntity(String.class));
            JSONArray jsonArray = new JSONArray(AESDecryption.decrypt(clientResponse.readEntity(String.class)));
            if (jsonArray.length() == 0) {
                logActivity(true, "invalid username!", username, programUrl, request, ipAddress);
                throw new ForbiddenException("invalid username!");
            }
            List<UserDetailDTO> userDetails = convertJsonArrayToUserDTOList(jsonArray);

           /* if (!CustomBcryptPasswordEncoder.getBcryptPasswordEncoder().matches(tokenSecret[1], jsonArray.getJSONObject(0).getString("password"))) {

                logActivity(true, "invalid credentials!", username, programUrl, request, ipAddress);
                throw new ForbiddenException("invalid credentials!");
            }*/
            //TODO : Add authorization logic
            //authorizedUserForIncomingURL(userDetails,requestUrl);
            /*if (!authorizedUser(jsonArray, requestUrl)) {
                String error = "unauthorized user!user does not have access for " + requestUrl;
                logActivity(true, "", username, programUrl, request, ipAddress);
                log.error("auth array:" + jsonArray);
                throw new UnAuthorizedException(error);
            }*/
        } catch (JSONException e) {
            String error = "Unable to authenticate and authorize the user!";
            logActivity(true, "", username, programUrl, request, ipAddress);
            log.error("Exception occurred", e);
            throw new BizException(error);
        }
    }

    private void authorizedUserForIncomingURL(List<UserDetailDTO> userDetails, String requestUrl) {
        List<UserDetailDTO> filteredPrivileges = userDetails.stream().filter(userdetail -> userdetail.getUrl().equalsIgnoreCase(requestUrl)).collect(Collectors.toList());
        if(filteredPrivileges.size() == 0){
            String userName = userDetails.get(0).getUserName();
            log.error("User :{} is not authorized to access URL :{} ",userName,requestUrl);
            throw new UnAuthorizedException("Unauthorized User");
        }
    }

    private List<UserDetailDTO> convertJsonArrayToUserDTOList(JSONArray jsonArray) {
        log.info("Converting user json array of length :{} to java objects ",jsonArray.length());
        try{
            List<UserDetailDTO> userDetails = new ArrayList<>();
            ObjectMapper mapper = new ObjectMapper();

            for (int i=0 ; i< jsonArray.length();i++){
                JSONObject jsonObject = jsonArray.getJSONObject(i);
                UserDetailDTO userDetailDTO = mapper.readValue(jsonObject.toString(), UserDetailDTO.class);
                userDetails.add(userDetailDTO);
            }
            return  userDetails;
        }catch (JSONException e){
            log.error(e.getMessage(),e);
            throw new BizException("Error while parsing ",e.getMessage());
        } catch (JsonMappingException e) {
            e.printStackTrace();
            throw new BizException("Error while parsing ",e.getMessage());
        } catch (JsonParseException e) {
            e.printStackTrace();
            throw new BizException("Error while parsing ",e.getMessage());
        } catch (IOException e) {
            e.printStackTrace();
            throw new BizException("Error while parsing ",e.getMessage());
        }


        /*final ObjectMapper objectMapper = new ObjectMapper();
        try{
            List<UserDetailDTO> userDetails = objectMapper.readValue(jsonArray, new TypeReference<List<UserDetailDTO>>(){});
            log.info("User details extracted : ",userDetails.size());
            return userDetails;
        } catch (JsonMappingException e) {
            e.printStackTrace();
            throw  new BizException("Error while parsing JSON Array to UserDetails");
        } catch (JsonParseException e) {
            e.printStackTrace();
            throw  new BizException("Error while parsing JSON Array to UserDetails");
        } catch (IOException e) {
            e.printStackTrace();
            throw  new BizException("Error while parsing JSON Array to UserDetails");
        }*/
    }

    private boolean authorizedUser(JSONArray jsonArray, String requestUrl) {
        return jsonArray.toString().contains("\"url\":\"" + requestUrl + "\"");
    }

    private long getTokenLastAccessedTimeInMillis(final String userName) {
        isUserNameBlank(userName);
        if (!(TOKEN_MAP.containsKey(concat(userName, USER_TOKEN_GENERATION_DATE_TIME_STAMP_SUFFIX)))) {
            createNewDateTimeStampForUser(userName);
        }
        return (Long.parseLong(TOKEN_MAP.get(concat(userName, USER_TOKEN_GENERATION_DATE_TIME_STAMP_SUFFIX))));
    }

    private boolean hasTokenExpired(final String userName) {
        return Math.abs(new Date().getTime() - getTokenLastAccessedTimeInMillis(userName)) > (TOKEN_EXPIRY_DURATION_IN_SECONDS * 1000);
    }

    private void isUserNameBlank(final String userName) {
        if (StringUtils.isBlank(userName)) {
            log.error("Username is mandatory!");
            throw new UnAuthorizedException("User name is mandatory!");
        }
    }
    private String concat(final String... inputArray) {
        final StringBuilder result = new StringBuilder();
        for (int i = 0; i < inputArray.length; i++) {
            result.append(inputArray[i]);
        }
        return result.toString();
    }

    private void createNewDateTimeStampForUser(final String userName) {
        TOKEN_MAP.put(concat(userName, USER_TOKEN_GENERATION_DATE_TIME_STAMP_SUFFIX), String.valueOf(new Date().getTime()));
    }
    public String parseUsernameFromJwt(String token) {
        String jwtToken = token.replaceAll("Bearer ","");
        if(isTokenExpired(jwtToken)){
            log.error("Token has Expired. ");
            throw new BizException("Given token is expired.");
        }
        final JwtParser jwtParser = Jwts.parser();
        if (!jwtParser.isSigned(jwtToken)) {
            log.error("The provided JWT token doesn't contain any signature and thus can be malicious and can't be trusted");
            throw new BizException("Unsigned token found, signature is mandatory");
        }
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(jwtToken).getBody().getAudience();
    }

//    private boolean validateAppUser(String userName) {
//        return applicationLevelUserName.equals(userName) ? true:false;
//    }
    private boolean validateAppUser(String userName) {
    	if(applicationLevelUserName.equals(userName)) {
    		return true;
    	}
    	else if(applicationLevelUserNameNew.equals(userName)) {
    		return true;
    	}
    	else {
    		return false;
    	}

        
    }

    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }


    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }


    public <T> T extractClaim(String token , Function<Claims, T> claimResolver) {
        final Claims claim= extractAllClaims(token);
        return claimResolver.apply(claim);
    }


    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
    }



}
