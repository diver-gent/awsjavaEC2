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

import java.io.IOException;


public class awsjavaEC2 {

    private static final String SECURITY_GROUP = "btownsSG";
    private static final String SG_DESC = "my security group";
    private static final String KEY_NAME = "btownsKey";
    private static final String AMI = "ami-d5c5d1e5";
    private static final String AMI_TYPE = "t2.micro";
    private static final String IP_RANGE = "0.0.0.0/0";
    private static final String PROTOCOL = "tcp";
    private static final Integer PORT = 22;

    public static void main(String [] args) throws IOException {

        AWSCredentials creds = getCreds();
        AmazonEC2Client ec2 = getEc2(creds);

        CreateSecurityGroupRequest csgRequest = createRequest(SECURITY_GROUP, SG_DESC);
        ec2.createSecurityGroup(csgRequest);

        IpPermission ipPerms = setIpPerms(IP_RANGE, PROTOCOL, PORT,PORT);

        AuthorizeSecurityGroupIngressRequest authSGInReq = getAuthSGInReq(SECURITY_GROUP, ipPerms);
        ec2.authorizeSecurityGroupIngress(authSGInReq);

        KeyPair keyPair = createKPReq(KEY_NAME, ec2);

        String privateKey = keyPair.getKeyMaterial();
        System.out.println("KEY " + privateKey);

        RunInstancesRequest runInstancesRequest =
                new RunInstancesRequest();

        runInstancesRequest.withImageId(AMI)
                .withInstanceType(AMI_TYPE)
                .withMinCount(1)
                .withMaxCount(1)
                .withKeyName(KEY_NAME)
                .withSecurityGroups(SECURITY_GROUP);

        RunInstancesResult runInstancesResult =
                ec2.runInstances(runInstancesRequest);

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
