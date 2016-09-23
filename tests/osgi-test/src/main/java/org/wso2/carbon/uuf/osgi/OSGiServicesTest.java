package org.wso2.carbon.uuf.osgi;

import org.ops4j.pax.exam.*;
import org.ops4j.pax.exam.CoreOptions;
import org.ops4j.pax.exam.ExamFactory;
import org.ops4j.pax.exam.Option;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerClass;
import org.ops4j.pax.exam.testng.listener.PaxExam;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;
import org.testng.Assert;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.container.CarbonContainerFactory;
import org.wso2.carbon.kernel.utils.CarbonServerInfo;
import org.wso2.carbon.uuf.core.API;
import org.wso2.carbon.uuf.sample.petsstore.bundle.service.PetsStoreService;

import javax.inject.Inject;
import java.util.Map;

import static org.ops4j.pax.exam.CoreOptions.mavenBundle;
import static sun.plugin.javascript.navig.JSType.Option;

@Listeners(PaxExam.class)
@ExamFactory(CarbonContainerFactory.class)
@ExamReactorStrategy(PerClass.class)
public class OSGiServicesTest {
    @Inject
    private BundleContext bundleContext;

    @Inject
    private CarbonServerInfo carbonServerInfo;

    @Configuration
    public Option[] config() {
        return CoreOptions.options(
                getBundleOption("org.wso2.carbon.deployment.engine", "org.wso2.carbon.deployment"),
                getBundleOption("org.wso2.carbon.deployment.notifier", "org.wso2.carbon.deployment"),
                getBundleOption("geronimo-jms_1.1_spec", "org.apache.geronimo.specs"),
                getBundleOption("commons-pool", "commons-pool.wso2"),
                getBundleOption("org.wso2.carbon.uuf.sample.pets-store.bundle", "org.wso2.carbon.uuf.sample"),
                getBundleOption("commons-io", "commons-io.wso2"),
                getBundleOption("org.wso2.carbon.jndi", "org.wso2.carbon.jndi"),
                getBundleOption("org.wso2.carbon.caching", "org.wso2.carbon.caching"),
                getBundleOption("gson", "com.google.code.gson"),
                getBundleOption("guava", "com.google.guava"),
                getBundleOption("commons-lang3", "org.apache.commons"),
                getBundleOption("asm", "org.ow2.asm")
        );
    }

    @Test
    public void testPetsStoreService() {
        ServiceReference serviceReference = bundleContext.getServiceReference(PetsStoreService.class.getName());
        Assert.assertNotNull(serviceReference, "Pets Store Service Reference is null.");

        PetsStoreService petsStoreService = (PetsStoreService) bundleContext.getService(serviceReference);
        Assert.assertNotNull(petsStoreService, "Pets Store Service is null.");

        String serviceOutput = petsStoreService.getHelloMessage("Alice");
        Assert.assertEquals(serviceOutput, "Hello Alice!",
                            "Pets Store Service, getHelloMessage is not working properly.");
    }

    @Test
    public void testOSGiServicesAPI() {
        String outputForCallOSGiService = API.callOSGiService(
                "org.wso2.carbon.uuf.sample.petsstore.bundle.service.PetsStoreService",
                "getHelloMessage", "Bob").toString();
        Assert.assertEquals(outputForCallOSGiService, "Hello Bob!");

        Map<String, Object> osgiServices = API.getOSGiServices(
                "org.wso2.carbon.uuf.sample.petsstore.bundle.service.PetsStoreService");
        Object petsStoreService = osgiServices.get(
                "org.wso2.carbon.uuf.sample.petsstore.bundle.internal.impl.PetsManagerImpl");
        Assert.assertNotNull(petsStoreService,
                             "PetsManagerImpl service wasn't retrieved from getOSGiServices method.");

        String serviceOutput = ((PetsStoreService) petsStoreService).getHelloMessage("Alice");
        Assert.assertEquals(serviceOutput, "Hello Alice!");
    }

    /**
     * Returns the maven bundle option for pax-exam container.
     *
     * @param artifactId Bundle artifact id
     * @param groupId    Bundle group id
     * @return Maven bundle option
     */
    private Option getBundleOption(String artifactId, String groupId) {
        return mavenBundle().artifactId(artifactId).groupId(groupId).versionAsInProject();
    }
}
