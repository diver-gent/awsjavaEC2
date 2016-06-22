/**
 * Created by btowns on 6/20/16.
 */

import com.amazonaws.AmazonClientException;
import com.amazonaws.auth.profile.ProfileCredentialsProvider;
import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.AmazonEC2Client;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.services.ec2.model.CreateSecurityGroupRequest;
import com.amazonaws.services.ec2.model.CreateSecurityGroupResult;
import com.amazonaws.services.ec2.model.IpPermission;
import com.amazonaws.services.ec2.model.AuthorizeSecurityGroupIngressRequest;
import com.amazonaws.services.ec2.model.CreateKeyPairRequest;
import com.amazonaws.services.ec2.model.CreateKeyPairResult;
import com.amazonaws.services.ec2.model.KeyPair;
import com.amazonaws.services.ec2.model.RunInstancesRequest;
import com.amazonaws.services.ec2.model.RunInstancesResult;

import java.io.InputStream;
import java.io.IOException;
import java.util.Properties;


public class awsjavaEC2 {

    private static final String PROPS = "config.properties";

    public static void main(String [] args) throws IOException {

        Properties props = loadProps();

        AWSCredentials creds = getCreds();
        AmazonEC2Client ec2 = getEc2(creds);

        CreateSecurityGroupRequest csgRequest = createRequest(
                props.getProperty("SECURITY_GROUP"),
                props.getProperty("SG_DESC"));
        ec2.createSecurityGroup(csgRequest);

        IpPermission ipPerms = setIpPerms(
                props.getProperty("IP_RANGE"),
                props.getProperty("PROTOCOL"),
                Integer.parseInt(props.getProperty("FROM")),
                Integer.parseInt(props.getProperty("TO")));

        AuthorizeSecurityGroupIngressRequest authSGInReq = getAuthSGInReq(
                props.getProperty("SECURITY_GROUP"), ipPerms);
        ec2.authorizeSecurityGroupIngress(authSGInReq);

        KeyPair keyPair = createKPReq(
                props.getProperty("KEY_NAME"), ec2);

        String privateKey = keyPair.getKeyMaterial();
        System.out.println("KEY " + privateKey);

        RunInstancesRequest runInstancesRequest =
                new RunInstancesRequest();

        runInstancesRequest.withImageId(
                props.getProperty("AMI"))
                .withInstanceType(props.getProperty("AMI_TYPE"))
                .withMinCount(1)
                .withMaxCount(1)
                .withKeyName(props.getProperty("KEY_NAME"))
                .withSecurityGroups(props.getProperty("SECURITY_GROUP"));

        RunInstancesResult runInstancesResult =
                ec2.runInstances(runInstancesRequest);

    }

    private static Properties loadProps() throws IOException{
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
        Properties props = new Properties();
        InputStream propStream = loader.getResourceAsStream(PROPS);
        props.load(propStream);
    }

    private static AWSCredentials getCreds() {
        AWSCredentials creds = null;
        try {
            creds = new ProfileCredentialsProvider().getCredentials();
        } catch (Exception e) {
            System.out.println("Cannot load credentials." + e);
        }
        return creds;
    }

    private static AmazonEC2Client getEc2(AWSCredentials creds) {
        AmazonEC2Client ec2 = new AmazonEC2Client(creds);
        Region usWest2 = Region.getRegion(Regions.US_WEST_2);
        ec2.setRegion(usWest2);
        return ec2;
    }

    private static CreateSecurityGroupRequest createRequest(String name, String desc) {
        CreateSecurityGroupRequest csgRequest = new CreateSecurityGroupRequest();
        csgRequest.withGroupName(name).withDescription(desc);
        return csgRequest;
    }

    private static IpPermission setIpPerms(String range, String protocol, Integer from, Integer to) {
        IpPermission ipPerms =
                new IpPermission();
        ipPerms.withIpRanges(range)
                .withIpProtocol(protocol)
                .withFromPort(from)
                .withToPort(to);
        return ipPerms;
    }

    private static AuthorizeSecurityGroupIngressRequest getAuthSGInReq(String name, IpPermission perms) {
        AuthorizeSecurityGroupIngressRequest authSGInReq =
                new AuthorizeSecurityGroupIngressRequest();
        authSGInReq.withGroupName(name)
                .withIpPermissions(perms);
        return authSGInReq;
    }

    private static KeyPair createKPReq(String name, AmazonEC2Client ec2) {
        CreateKeyPairRequest createKPReq = new CreateKeyPairRequest();
        createKPReq.withKeyName(name);
        CreateKeyPairResult createKeyPairResult =
                ec2.createKeyPair(createKPReq);
        KeyPair keyPair = new KeyPair();
        keyPair = createKeyPairResult.getKeyPair();
        return keyPair;
    }
}
