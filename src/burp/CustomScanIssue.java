package burp;

import java.net.URL;

public class CustomScanIssue implements IScanIssue {

	private URL url;
    private String issueName;
    private int issueType;
    /* "High", "Medium", "Low", "Information", "False positive*/
    private String severity;
    /*"Certain", "Firm", "Tentative"*/
    private String confidence;
    private String issueBackground;
    private String remediationBackground;
    private String issueDetail;
    private String remediationDetail;
    private IHttpService httpService;
    private IHttpRequestResponse httpMessages;
    
    public CustomScanIssue(
    		URL url,
    		String issueName,
    		int issueType,
    		String severity,
    		String confidence,
    		String issueBackground,
    		String remediationBackground,
    		String issueDetail,
    		String remediationDetail,
    		IHttpService httpService,
    		IHttpRequestResponse httpMessages
    		) {
    	this.url = url;
        this.issueName = issueName;
        this.issueType = issueType;
        this.severity = severity;
        this.confidence = confidence;
        this.issueBackground = issueBackground;
        this.remediationBackground = remediationBackground;
        this.issueDetail = issueDetail;
        this.remediationDetail = remediationDetail;
        this.httpService = httpService;
        this.httpMessages = httpMessages;
    }      
    
    @Override
    public URL getUrl() {
        return url;
    }

    @Override
    public String getIssueName() {
        return issueName;
    }

    @Override
    public int getIssueType() {
        return issueType;
    }

    @Override
    public String getSeverity() {
        return severity;
    }

    @Override
    // "Certain", "Firm" or "Tentative"
    public String getConfidence() {
        return confidence;
    }

    @Override
    public String getIssueBackground() {
        return issueBackground;
    }

    @Override
    public String getRemediationBackground() {
        return remediationBackground;
    }

    @Override
    public String getIssueDetail() {
        return issueDetail;
    }

    @Override
    public String getRemediationDetail() {
        return remediationDetail;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return new IHttpRequestResponse[]{httpMessages};
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }

}
