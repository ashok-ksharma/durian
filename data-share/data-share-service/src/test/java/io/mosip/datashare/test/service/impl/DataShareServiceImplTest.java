package io.mosip.datashare.test.service.impl;

import static io.mosip.commons.khazana.constant.KhazanaErrorCodes.OBJECT_STORE_NOT_ACCESSIBLE;
import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import io.mosip.commons.khazana.exception.ObjectStoreAdapterException;
import io.mosip.datashare.exception.PolicyException;
import io.mosip.kernel.core.util.StringUtils;
import org.apache.commons.io.IOUtils;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.api.AfterEach;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockserver.client.MockServerClient;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.modules.junit4.PowerMockRunnerDelegate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.env.Environment;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.util.ReflectionTestUtils;

import io.mosip.commons.khazana.spi.ObjectStoreAdapter;
import io.mosip.datashare.dto.DataShare;
import io.mosip.datashare.dto.DataShareDto;
import io.mosip.datashare.dto.PolicyAttributesDto;
import io.mosip.datashare.dto.PolicyResponseDto;
import io.mosip.datashare.exception.DataShareExpiredException;
import io.mosip.datashare.exception.DataShareNotFoundException;
import io.mosip.datashare.exception.FileException;
import io.mosip.datashare.service.impl.DataShareServiceImpl;
import io.mosip.datashare.util.CacheUtil;
import io.mosip.datashare.util.DigitalSignatureUtil;
import io.mosip.datashare.util.EncryptionUtil;
import io.mosip.datashare.util.PolicyUtil;
import io.mosip.kernel.core.util.CryptoUtil;
import org.springframework.util.StopWatch;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;

@RunWith(PowerMockRunner.class)
@PowerMockIgnore({ "com.sun.org.apache.xerces.*", "javax.xml.*", "org.xml.*", "javax.management.*", "org.w3c.dom.*",
		"com.sun.org.apache.xalan.*", "javax.net.ssl.*"})
@PowerMockRunnerDelegate(SpringRunner.class)
@PrepareForTest(value = { URL.class, CryptoUtil.class })
public class DataShareServiceImplTest {

	@Mock
	private PolicyUtil policyUtil;

	/** The encryption util. */
	@Mock
	private EncryptionUtil encryptionUtil;

	@Mock
	private CacheUtil cacheUtil;

	/** The env. */
	@Mock
	private Environment env;

	/** The digital signature util. */
	@Mock
	private DigitalSignatureUtil digitalSignatureUtil;

	/** The object store adapter. */
	@Mock
	ObjectStoreAdapter objectStoreAdapter;

	@InjectMocks
	DataShareServiceImpl dataShareServiceImpl;

	private PolicyResponseDto policyResponseDto;

	private byte[] dataBytes;

	private String SUBSCRIBER_ID = "subscriberid";
	
	private String POLICY_ID = "policyid";

	Map<String, Object> metaDataMap;

	MockMultipartFile multiPartFile;

	InputStream inputStream;

	private ClientAndServer mockServer;
	private MockServerClient mockServerClient;

	private PolicyAttributesDto policyAttributesDto;
	@Before
	public void setUp() throws Exception {
		ReflectionTestUtils.setField(dataShareServiceImpl, "servletPath", "/");
		ReflectionTestUtils.setField(dataShareServiceImpl, "isShortUrl", false);
		ReflectionTestUtils.setField(dataShareServiceImpl, "httpProtocol", "https");
		Mockito.when(env.getProperty("mosip.data.share.datetime.pattern"))
				.thenReturn("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
		metaDataMap = new HashMap<String, Object>();
		metaDataMap.put("transactionsallowed", "2");
		ClassLoader classLoader = getClass().getClassLoader();
		File file = new File(classLoader.getResource("test.txt").getFile());

		inputStream = new FileInputStream(file);
		dataBytes = IOUtils.toByteArray(inputStream);
		multiPartFile = new MockMultipartFile("file", "NameOfTheFile", "multipart/form-data",
				new ByteArrayInputStream(dataBytes));

		policyResponseDto = new PolicyResponseDto();
		DataShareDto dataSharePolicies = new DataShareDto();
		dataSharePolicies.setEncryptionType("Partner Based");
		dataSharePolicies.setShareDomain("dev.mosip.net");
		dataSharePolicies.setTransactionsAllowed("2");
		dataSharePolicies.setValidForInMinutes("60");
		dataSharePolicies.setSource("");
		dataSharePolicies.setTypeOfShare("");
		policyAttributesDto = new PolicyAttributesDto();
		policyAttributesDto.setDataSharePolicies(dataSharePolicies);
		policyResponseDto.setPolicies(policyAttributesDto);
		Mockito.when(policyUtil.getPolicyDetail(Mockito.anyString(), Mockito.anyString()))
				.thenReturn(policyResponseDto);
		Mockito.when(encryptionUtil.encryptData(Mockito.any(), Mockito.anyString()))
				.thenReturn(dataBytes);
		
		Mockito.when(digitalSignatureUtil.jwtSign(Mockito.any(), Mockito.anyString(), Mockito.anyString(),
				Mockito.anyString(),
				Mockito.anyString()))
		.thenReturn(dataBytes.toString());
		Mockito.when(objectStoreAdapter.putObject(Mockito.anyString(), Mockito.anyString(), Mockito.any(),
				Mockito.any(), Mockito.anyString(),
				Mockito.any())).thenReturn(true);
		Mockito.when(objectStoreAdapter.addObjectMetaData(Mockito.anyString(), Mockito.anyString(), Mockito.any(),
				Mockito.any(), Mockito.anyString(),
				Mockito.any())).thenReturn(metaDataMap);

		
		Mockito.when(objectStoreAdapter.getMetaData(Mockito.anyString(), Mockito.anyString(), Mockito.any(),
				Mockito.any(), Mockito.anyString()
				)).thenReturn(metaDataMap);
		Mockito.when(objectStoreAdapter.getObject(Mockito.anyString(), Mockito.anyString(), Mockito.any(),
				Mockito.any(), Mockito.anyString()))
				.thenReturn(inputStream);
		Mockito.when(cacheUtil.getShortUrlData(Mockito.any(), Mockito.any(), Mockito.any(),
				Mockito.any()))
				.thenReturn(POLICY_ID + "," + SUBSCRIBER_ID + "," + "dfg3456f");
		mockServer = ClientAndServer.startClientAndServer(1100);
		mockServerClient = new MockServerClient("localhost", 1100);
	}

	@Test
	public void createDataShareSuccessWithoutEncryptionTest() {

		policyResponseDto = new PolicyResponseDto();
		DataShareDto dataSharePolicies = new DataShareDto();
		dataSharePolicies.setEncryptionType("none");
		dataSharePolicies.setShareDomain("dev.mosip.net");
		dataSharePolicies.setTransactionsAllowed("2");
		dataSharePolicies.setValidForInMinutes("60");
		policyAttributesDto = new PolicyAttributesDto();
		policyAttributesDto.setDataSharePolicies(dataSharePolicies);
		policyResponseDto.setPolicies(policyAttributesDto);
		Mockito.when(policyUtil.getPolicyDetail(Mockito.anyString(), Mockito.anyString()))
				.thenReturn(policyResponseDto);
		DataShare dataShare = dataShareServiceImpl.createDataShare(POLICY_ID, SUBSCRIBER_ID, multiPartFile, null);
		assertEquals("Data Share created successfully", POLICY_ID, dataShare.getPolicyId());
	}

	@Test
	public void createDataShareSuccessTest() {

		DataShare dataShare = dataShareServiceImpl.createDataShare(POLICY_ID, SUBSCRIBER_ID, multiPartFile, null);
		assertEquals("Data Share created successfully", POLICY_ID, dataShare.getPolicyId());
	}

	@Test
	public void createDataShareSuccesswithShortUrlTest() {
		Mockito.when(env.getProperty("mosip.data.share.key.length")).thenReturn("8");
		ReflectionTestUtils.setField(dataShareServiceImpl, "isShortUrl", true);
		DataShare dataShare = dataShareServiceImpl.createDataShare(POLICY_ID, SUBSCRIBER_ID, multiPartFile, null);
		assertEquals("Data Share created successfully", POLICY_ID, dataShare.getPolicyId());
	}

	@Test(expected = FileException.class)
	public void fileExceptionTest() {
		multiPartFile=null;
		dataShareServiceImpl.createDataShare(POLICY_ID, SUBSCRIBER_ID, multiPartFile, null);
	}

	@Test
	public void getDataFileSuccessTest() {

		assertNotNull(dataShareServiceImpl.getDataFile(POLICY_ID, SUBSCRIBER_ID, "12dfsdff"));
	}

	@Test(expected = DataShareNotFoundException.class)
	public void dataShareNotFoundExceptionTest() {
		Mockito.when(objectStoreAdapter.getObject(Mockito.anyString(), Mockito.anyString(), Mockito.any(),
				Mockito.any(), Mockito.anyString()))
				.thenReturn(null);
		dataShareServiceImpl.getDataFile(POLICY_ID, SUBSCRIBER_ID, "12dfsdff");
	}
	
	
	@Test(expected = DataShareNotFoundException.class)
	public void testMetaDataNull() {

		Mockito.when(objectStoreAdapter.getMetaData(Mockito.anyString(), Mockito.anyString(), Mockito.any(),
				Mockito.any(), Mockito.anyString())).thenReturn(null);
		dataShareServiceImpl.getDataFile(POLICY_ID, SUBSCRIBER_ID, "12dfsdff");
	}
	@Test(expected = DataShareExpiredException.class)
	public void dataShareExpiredExceptionTest() {
		metaDataMap.put("transactionsallowed", "0");
		dataShareServiceImpl.getDataFile(POLICY_ID, SUBSCRIBER_ID, "12dfsdff");
	}

	@Test
	public void getDataFileWithShortKeySuccessTest() {

		ReflectionTestUtils.setField(dataShareServiceImpl, "isShortUrl", true);
		assertNotNull(dataShareServiceImpl.getDataFile("12dfsdff"));
	}

	@Test(expected = DataShareNotFoundException.class)
	public void getDataFileFailureTest() {
		Mockito.when(cacheUtil.getShortUrlData(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
				.thenReturn("");
		dataShareServiceImpl.getDataFile("12dfsdff");
	}

	@Test(expected = DataShareNotFoundException.class)
	public void getDataFileExceptionTest() {
		Mockito.when(cacheUtil.getShortUrlData(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
				.thenReturn("" + "," + "");
		dataShareServiceImpl.getDataFile("12dfsdff");
	}

	@Test(expected = DataShareNotFoundException.class)
	public void getDataFileDataShareNotFoundExceptionTest() {
		Mockito.doThrow(new ObjectStoreAdapterException(OBJECT_STORE_NOT_ACCESSIBLE.getErrorCode(), OBJECT_STORE_NOT_ACCESSIBLE.getErrorMessage(), new Throwable())).when(objectStoreAdapter).getObject(Mockito.anyString(),Mockito.anyString(),Mockito.any(),Mockito.any(),Mockito.anyString());
		dataShareServiceImpl.getDataFile("12dfsdff");
	}

	@Test
	public void createStaticDataShareSuccessTest() {
		ReflectionTestUtils.setField(dataShareServiceImpl, "standaloneModeEnabled", true);
		DataShareDto dataShareDto = new DataShareDto();
		dataShareDto.setTypeOfShare("");
		dataShareDto.setTransactionsAllowed("2");
		dataShareDto.setShareDomain("datashare.datashare");
		dataShareDto.setEncryptionType("NONE");
		dataShareDto.setSource("");
		dataShareDto.setValidForInMinutes("30");
		Mockito.when(policyUtil.getStaticDataSharePolicy(Mockito.anyString(), Mockito.anyString(), Mockito.isNull()))
				.thenReturn(dataShareDto);
		String policyId = "static-policyid";
		String subscriberId = "static-subscriberid";
		DataShare dataShare = dataShareServiceImpl.createDataShare(policyId, subscriberId, multiPartFile, null);
		assertEquals("Data Share created successfully", policyId, dataShare.getPolicyId());
	}

	@Test(expected = PolicyException.class)
	public void createStaticDataSharePolicyExceptionTest() {
		ReflectionTestUtils.setField(dataShareServiceImpl, "standaloneModeEnabled", true);
		Mockito.doThrow(new PolicyException()).
				when(policyUtil).getStaticDataSharePolicy(Mockito.anyString(), Mockito.anyString(), Mockito.isNull());
		dataShareServiceImpl.createDataShare(POLICY_ID, SUBSCRIBER_ID, multiPartFile, null);
	}

	@Test
	public void disableSignatureSuccessTest() {
		ReflectionTestUtils.setField(dataShareServiceImpl, "isSignatureDisabled", true);
		DataShare dataShare = dataShareServiceImpl.createDataShare(POLICY_ID, SUBSCRIBER_ID, multiPartFile, null);
		Mockito.verify(digitalSignatureUtil, Mockito.never()).jwtSign(Mockito.any(),
				Mockito.anyString(), Mockito.anyString(), Mockito.anyString(), Mockito.anyString());
		assertEquals("Data Share created successfully", POLICY_ID, dataShare.getPolicyId());
	}

	@Test
	public void enableSignatureSuccessTest() {
		ReflectionTestUtils.setField(dataShareServiceImpl, "isSignatureDisabled", false);
		DataShare dataShare = dataShareServiceImpl.createDataShare(POLICY_ID, SUBSCRIBER_ID, multiPartFile, null);
		Mockito.verify(digitalSignatureUtil, Mockito.atLeastOnce()).jwtSign(Mockito.any(),
				Mockito.anyString(), Mockito.anyString(), Mockito.anyString(), Mockito.anyString());
		assertEquals("Data Share created successfully", POLICY_ID, dataShare.getPolicyId());
	}

	@Test
	public void getDataFileWithUnlimitedUsageSuccessTest() {
		metaDataMap = new HashMap<String, Object>();
		metaDataMap.put("transactionsallowed", "-1");
		Mockito.when(objectStoreAdapter.getMetaData(Mockito.anyString(), Mockito.anyString(), Mockito.any(),
				Mockito.any(), Mockito.anyString()
		)).thenReturn(metaDataMap);
		dataShareServiceImpl.getDataFile(POLICY_ID, SUBSCRIBER_ID, "12dfsdff");
		Mockito.verify(objectStoreAdapter, Mockito.never()).decMetadata(Mockito.anyString(),
				Mockito.anyString(), Mockito.anyString(), Mockito.anyString(),
				Mockito.anyString(), Mockito.anyString());
	}

	@Test
	public void testRestTemplateTimeout() {
		mockServerClient.when(HttpRequest.request()
						.withMethod("GET")
						.withPath("/api/data"))
				.respond(HttpResponse.response()
						.withStatusCode(200)
						.withBody("Hello")
						.withDelay(TimeUnit.SECONDS, 10));

		StopWatch stopWatch = new StopWatch();
		stopWatch.start();
		assertThrows(ResourceAccessException.class, () -> {
			getRestTemplate().getForObject("http://localhost:1100/api/data", String.class);
		});
		stopWatch.stop();
		var elapsed = stopWatch.getTotalTimeMillis();
		System.out.println("Total time : " + elapsed);
	}

	private RestTemplate getRestTemplate()
			throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
		var connectionManagerBuilder = PoolingHttpClientConnectionManagerBuilder.create();
		TrustStrategy acceptingTrustStrategy = (X509Certificate[] chain, String authType) -> true;
		SSLContext sslContext = org.apache.http.ssl.SSLContexts.custom()
				.loadTrustMaterial(acceptingTrustStrategy).build();
		SSLConnectionSocketFactory csf = new SSLConnectionSocketFactory(sslContext, new HostnameVerifier() {
			public boolean verify(String arg0, SSLSession arg1) {
				return true;
			}
		});
		connectionManagerBuilder.setSSLSocketFactory(csf);
		var connectionManager = connectionManagerBuilder.build();

		HttpClientBuilder httpClientBuilder = HttpClients.custom()
				.setConnectionManager(connectionManager)
				.setDefaultRequestConfig(RequestConfig.custom().setResponseTimeout(Long.parseLong("5000"), TimeUnit.MILLISECONDS).build())
				.disableCookieManagement();

		HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
		requestFactory.setHttpClient(httpClientBuilder.build());
        return new RestTemplate(requestFactory);
	}

	@AfterEach
	public void tearDown() {
		// Stop the MockServer after the test
		mockServer.stop();
	}
}
