package burp;

import java.util.ArrayList;
import java.util.List;
import java.io.*;


public class BurpExtender implements IBurpExtender, IScannerCheck{

	private PrintWriter stdout;
	private PrintWriter stderr;
	
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	
	public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks){
		this.callbacks = callbacks;
		
		this.helpers = callbacks.getHelpers();
		stdout = new PrintWriter(callbacks.getStdout(), true);
		stderr = new PrintWriter(callbacks.getStderr(), true);
		callbacks.setExtensionName("this extension that checking orderby sql injection");
		callbacks.registerScannerCheck(this);
	}
	
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse){
		List<IScanIssue> issues = new ArrayList<IScanIssue>();
//		SqlInject s = new SqlInject();
//		issues = s.scan(callbacks, baseRequestResponse);
		return issues;
	}
	
	public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint){
		List<IScanIssue> issues = new ArrayList<IScanIssue>();
		SqlInject s = new SqlInject();
		try{
		issues = s.scan(callbacks, baseRequestResponse, insertionPoint);
		}catch (UnsupportedEncodingException e){
			e.printStackTrace();
		}
		return issues;
	}
	
	public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        // This method is called when multiple issues are reported for the same URL 
        // path by the same extension-provided check. The value we return from this 
        // method determines how/whether Burp consolidates the multiple issues
        // to prevent duplication
        //
        // Since the issue name is sufficient to identify our issues as different,
        // if both issues have the same name, only report the existing issue
        // otherwise report both issues
        if (existingIssue.getIssueName().equals(newIssue.getIssueName())) {
            return -1;
        } else {
            return 0;
        }
	}
}
