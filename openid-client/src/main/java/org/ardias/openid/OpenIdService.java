package org.ardias.openid;

import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.commons.lang3.StringUtils;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.consumer.VerificationResult;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.discovery.Identifier;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.AuthSuccess;
import org.openid4java.message.MessageException;
import org.openid4java.message.MessageExtension;
import org.openid4java.message.ParameterList;
import org.openid4java.message.ax.AxMessage;
import org.openid4java.message.ax.FetchResponse;
import org.openid4java.message.sreg.SRegMessage;
import org.openid4java.message.sreg.SRegResponse;

@Path("openid")
public class OpenIdService {

    @Context
    protected ServletContext context;

    private static final String DISCOVERED = "discovered";

    private static Map<String, Object> cache = new HashMap<>();
    private static ConsumerManager manager = new ConsumerManager();

    private static Properties props = new Properties();

    public OpenIdService() throws IOException {
        if (props.isEmpty()) {
            this.props.load(
                this.getClass().getClassLoader().getResourceAsStream("config.properties"));
        }
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Path("auth")
    public Response authenticate(
            @Context HttpServletRequest request) {

        try {
            final List<DiscoveryInformation> discoveries = manager.discover(props.getProperty("openid.user.identifier"));

            final boolean associate = Boolean.parseBoolean(props.getProperty("openid.associate"));
            if(!associate) {
                manager.setAllowStateless(true);
                manager.setMaxAssocAttempts(0);
            }

            //even though there is a call to associate if the maxAttemps is 0 there won't
            //be any attempt to associate
            final DiscoveryInformation discoveryInformation = manager.associate(discoveries);
            cache.put(DISCOVERED, discoveryInformation);

            String openIdCallbackUrl = props.getProperty("openid.callbackurl");

            AuthRequest authRequest =
                manager.authenticate(discoveryInformation, openIdCallbackUrl);

            String openIdUrl = authRequest.getDestinationUrl(true);

            return Response.temporaryRedirect(new URI(openIdUrl)).build();
        } catch (Exception e) {
            return Response.serverError().entity(e.toString()).build();
        }

    }

    @GET
    @Path("callback")
    public Response openid(@Context HttpServletRequest request)
            throws MessageException {
        ParameterList openidResp =new ParameterList(request.getParameterMap());
        DiscoveryInformation discovered = (DiscoveryInformation) cache.get(DISCOVERED);

        //build the 'verification url' to verify the authentication response
        //this can also be done with a 'verification service' but we do it locally here
        StringBuffer receivingURL = request.getRequestURL();
        String queryString = request.getQueryString();
        if (queryString != null && queryString.length() > 0) {
            receivingURL.append("?").append(request.getQueryString());
        }

        VerificationResult verification;
        try {
            verification = manager.verify(receivingURL.toString(),openidResp, discovered);
        } catch (Exception e) {
            return Response.serverError().entity(e.toString()).build();
        }

        if (verification != null) {
            Identifier verified = verification.getVerifiedId();
            if (verified != null) {
                AuthSuccess authSuccess =
                    (AuthSuccess) verification.getAuthResponse();

                //get Simple Registration attributes if available
                final Map<String, String> srMap =
                    receiveSimpleRegistration(request, authSuccess);
                //get Attribute Exchange attributes if available
                final Map<String, String> axMap =
                    receiveAttributeExchange(request, authSuccess);

                final Map<String, String> attributesMap = new HashMap<>();
                attributesMap.putAll(srMap);
                attributesMap.putAll(axMap);

                //build 'response' with the verification result and all
                // the optional received attributes
                StringBuilder sb =
                    new StringBuilder("Verified :" + verified);
                sb.append(System.lineSeparator());
                for (Map.Entry<String, String> e : attributesMap.entrySet()) {
                    sb.append(e.getKey() + " : " + e.getValue())
                      .append(System.lineSeparator());
                }
                return Response.ok(sb.toString()).build();
                //return onVerificationSuccessful(authSuccess);

            } else {
                return Response.ok("Auth failed").build();
            }
        } else {
            return Response.ok("Something went wrong").build();
        }
    }

    private Map<String, String> receiveSimpleRegistration(
            HttpServletRequest httpReq, AuthSuccess authSuccess)
                    throws MessageException {
        Map<String, String> m = new HashMap<String, String>();
        if (authSuccess.hasExtension(SRegMessage.OPENID_NS_SREG)) {
            MessageExtension ext =
                authSuccess.getExtension(SRegMessage.OPENID_NS_SREG);
            if (ext instanceof SRegResponse) {
                SRegResponse sregResp = (SRegResponse) ext;
                for (Iterator iter =
                    sregResp.getAttributeNames().iterator(); iter
                        .hasNext();) {
                    String name = (String) iter.next();
                    String value = sregResp.getParameterValue(name);
                    m.put(name, value);

                }
            }
        }
        return m;
    }

    private Map<String, String> receiveAttributeExchange(
            HttpServletRequest httpReq, AuthSuccess authSuccess)
                    throws MessageException {

        Map<String, String> m = new HashMap<>();
        if (authSuccess.hasExtension(AxMessage.OPENID_NS_AX)) {
            FetchResponse fetchResp = (FetchResponse) authSuccess
                .getExtension(AxMessage.OPENID_NS_AX);

            List aliases = fetchResp.getAttributeAliases();
            Map attributes = new LinkedHashMap();
            for (Iterator iter = aliases.iterator(); iter.hasNext();) {
                String alias = (String) iter.next();
                List values = fetchResp.getAttributeValues(alias);
                if (values.size() > 0) {
                    String[] arr = new String[values.size()];
                    values.toArray(arr);
                    m.put(alias, StringUtils.join(arr));
                } else {
                    m.put(alias, "");
                }
            }
        }
        return m;
    }
    // @GET
    // @Path("code")
    // public Response requestAccessToProtectedResource(@QueryParam("code")
    // String code) {
    // //code accessToken ??
    // WebClient wc = WebClient.create(accessTokenServiceUri);
    // wc.accept("application/json");
    // wc.query("client_id",client_id);
    // wc.query("client_secret",client_secret);
    // wc.query("redirect_uri", "http://localhost:8080/cas-testing/protected");
    // wc.query("code",code);
    // final Response response = wc.get();
    //
    // if(response.getStatus() == 200) {
    // String line = "";
    // try {
    // line = new BufferedReader(new InputStreamReader((InputStream)
    // response.getEntity())).readLine();
    // } catch (IOException e) {
    // e.printStackTrace();
    // }
    // String[] access_token_parts = line.split("=");
    // String access_token = access_token_parts[1].split("&")[0];
    // return Response.seeOther(
    // UriBuilder.fromUri("http://localhost:8080/cas-testing/protected")
    // .replaceQuery("")
    // .build())
    // .header("Authorization","Bearer " + access_token)
    // .build();
    // } else {
    // return Response.serverError().entity(response).build();
    // }
    //
    // }

}
