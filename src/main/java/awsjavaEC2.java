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

    public static void main(String [] args) throws IOException {

        AWSCredentials creds = getCreds();
        AmazonEC2Client ec2 = getEc2(creds);
        CreateSecurityGroupRequest csgr = new CreateSecurityGroupRequest();
        csgr.withGroupName("BtownsSecurityGroup").withDescription("My security group");


        CreateSecurityGroupResult createSecurityGroupResult =
                ec2.createSecurityGroup(csgr);


        IpPermission ipPermission =
                new IpPermission();

        ipPermission.withIpRanges("0.0.0.0/0")
                .withIpProtocol("tcp")
                .withFromPort(22)
                .withToPort(22);

        AuthorizeSecurityGroupIngressRequest authorizeSecurityGroupIngressRequest =
                new AuthorizeSecurityGroupIngressRequest();

        authorizeSecurityGroupIngressRequest.withGroupName("BtownsSecurityGroup")
                .withIpPermissions(ipPermission);

        ec2.authorizeSecurityGroupIngress(authorizeSecurityGroupIngressRequest);

        CreateKeyPairRequest createKeyPairRequest = new CreateKeyPairRequest();

        createKeyPairRequest.withKeyName("btownsKey");

        CreateKeyPairResult createKeyPairResult =
                ec2.createKeyPair(createKeyPairRequest);

        KeyPair keyPair = new KeyPair();

        keyPair = createKeyPairResult.getKeyPair();

        String privateKey = keyPair.getKeyMaterial();
        System.out.println("KEY " + privateKey);

        RunInstancesRequest runInstancesRequest =
                new RunInstancesRequest();

        runInstancesRequest.withImageId("ami-3df3a80d")
                .withInstanceType("t2.micro")
                .withMinCount(1)
                .withMaxCount(1)
                .withKeyName("btownsKey")
                .withSecurityGroups("BtownsSecurityGroup");

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


}
