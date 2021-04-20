package idscp2server;

import de.fhg.aisec.ids.idscp2.app_layer.AppLayerConnection;
import de.fhg.aisec.ids.idscp2.default_drivers.daps.aisec_daps.AisecDapsDriver;
import de.fhg.aisec.ids.idscp2.default_drivers.daps.aisec_daps.AisecDapsDriverConfig;
import de.fhg.aisec.ids.idscp2.default_drivers.rat.dummy.RatProverDummy;
import de.fhg.aisec.ids.idscp2.default_drivers.rat.dummy.RatVerifierDummy;
import de.fhg.aisec.ids.idscp2.default_drivers.secure_channel.tlsv1_3.NativeTLSDriver;
import de.fhg.aisec.ids.idscp2.default_drivers.secure_channel.tlsv1_3.NativeTlsConfiguration;
import de.fhg.aisec.ids.idscp2.idscp_core.api.Idscp2EndpointListener;
import de.fhg.aisec.ids.idscp2.idscp_core.api.configuration.AttestationConfig;
import de.fhg.aisec.ids.idscp2.idscp_core.api.configuration.Idscp2Configuration;
import de.fhg.aisec.ids.idscp2.idscp_core.api.idscp_server.Idscp2Server;
import de.fhg.aisec.ids.idscp2.idscp_core.api.idscp_server.Idscp2ServerFactory;
import de.fhg.aisec.ids.idscp2.idscp_core.drivers.SecureChannelDriver;
import de.fhg.aisec.ids.idscp2.idscp_core.rat_registry.RatProverDriverRegistry;
import de.fhg.aisec.ids.idscp2.idscp_core.rat_registry.RatVerifierDriverRegistry;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Paths;


/**
 * @author I050368
 */
public class IDSServer{

    private static Logger LOG = LoggerFactory.getLogger(IDSServer.class);


	public static void main(String[] args) {
		
		startIDSServer();
	}
    
    
    public static void startIDSServer() {
    	
        try {
        	
            String host = "localhost";
           // host = "consumer-core";
            int port = 29292;
            String ksPath = "ssl/consumer-keystore.p12";
             
            String tsPath = "ssl/truststore.p12";
            
            
            // register rat drivers
            RatProverDriverRegistry.INSTANCE.registerDriver(
                    RatProverDummy.RAT_PROVER_DUMMY_ID, RatProverDummy::new, null
            );
            RatVerifierDriverRegistry.INSTANCE.registerDriver(
                    RatVerifierDummy.RAT_VERIFIER_DUMMY_ID, RatVerifierDummy::new, null
            );

            // create attestation config
            AttestationConfig localAttestationConfig = (new AttestationConfig.Builder())
                    .setSupportedRatSuite(new String[]{RatProverDummy.RAT_PROVER_DUMMY_ID})
                    .setExpectedRatSuite(new String[]{RatVerifierDummy.RAT_VERIFIER_DUMMY_ID})
                    .setRatTimeoutDelay(Long.parseLong("3600000"))
                    .build();

            // secure channel config
            NativeTlsConfiguration secureChannelConfig = (new NativeTlsConfiguration.Builder())
                    .setHost(host)
                    .setServerPort(port)
                    .setKeyPassword("password".toCharArray())
                    .setKeyStorePath(Paths.get(ksPath))
                    .setKeyStoreKeyType("RSA")
                    .setKeyStorePassword("password".toCharArray())
                    .setTrustStorePath(Paths.get(tsPath))
                    .setTrustStorePassword("password".toCharArray())
                    .setCertificateAlias("1.0.1")
                    .build();


            // create daps config
            AisecDapsDriverConfig dapsDriverConfig = (new AisecDapsDriverConfig.Builder())
                    .setDapsUrl("https://daps.aisec.fraunhofer.de")
                    .setKeyAlias("1")
                    .setKeyPassword("password".toCharArray())
                    .setKeyStorePath(Paths.get(ksPath))
                    .setKeyStorePassword("password".toCharArray())
                    .setTrustStorePath(Paths.get(tsPath))
                    .setTrustStorePassword("password".toCharArray())
                    .build();


            // create idscp configuration
            Idscp2Configuration serverConfiguration = (new Idscp2Configuration.Builder())
                    .setAttestationConfig(localAttestationConfig)
                    .setDapsDriver(new AisecDapsDriver(dapsDriverConfig))
                    .build();

            SecureChannelDriver<AppLayerConnection, NativeTlsConfiguration> secureChannelDriver = new NativeTLSDriver<>();

            Idscp2ServerFactory<AppLayerConnection, NativeTlsConfiguration> serverFactory =
                    new Idscp2ServerFactory<>(AppLayerConnection::new, appLayerConnection -> {
                        LOG.debug("New server connection: {}", appLayerConnection);
                    }, serverConfiguration, secureChannelDriver, secureChannelConfig);
                  
            Idscp2Server server = serverFactory.listen();
 
        } catch (Exception e) {
        	LOG.error("Failed to send message:" + e.getMessage());
            e.printStackTrace();
        }
    }





}
