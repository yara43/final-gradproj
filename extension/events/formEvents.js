import { extractRegisteredDomain } from '../engine/brandIdentity.js';
function createFormSecurityEvent(form) {
  let pageHostname = "";
  let actionHostname = "";
  let pageOrigin = "";
  try {
    const pageParsed = new URL(form.pageUrl.startsWith("http") ? form.pageUrl : "https://" + form.pageUrl);
    pageHostname = pageParsed.hostname.toLowerCase();
    pageOrigin = pageParsed.origin;
  } catch {
    pageHostname = form.pageUrl.toLowerCase();
    pageOrigin = form.pageUrl;
  }
  try {
    if (form.action && (form.action.startsWith("http") || form.action.startsWith("//"))) {
      const actionUrl = form.action.startsWith("//") ? "https:" + form.action : form.action;
      const actionParsed = new URL(actionUrl);
      actionHostname = actionParsed.hostname.toLowerCase();
    } else {
      actionHostname = pageHostname;
    }
  } catch {
    actionHostname = pageHostname;
  }
  const pageRegDomain = extractRegisteredDomain(pageHostname);
  const actionRegDomain = extractRegisteredDomain(actionHostname);
  const actionIsCrossOrigin = actionHostname !== "" && actionRegDomain !== pageRegDomain;
  const actionIsInsecure = form.action.toLowerCase().startsWith("http://");
  let formType = "GENERIC";
  if (form.has2FAField) {
    formType = "VERIFICATION_2FA";
  } else if (form.hasCreditCardField) {
    formType = "PAYMENT";
  } else if (form.hasPasswordField) {
    formType = "LOGIN";
  } else if (form.hasEmailOrUserField) {
    formType = "REGISTRATION";
  }
  let severity = "LOW";
  let eventType = "CREDENTIAL_FORM_DETECTED";
  let title = "Form Detected";
  let description = `Standard ${formType} form present.`;
  if (actionIsCrossOrigin && (form.hasPasswordField || form.hasCreditCardField || form.has2FAField)) {
    severity = "CRITICAL";
    eventType = "CROSS_ORIGIN_FORM_ACTION";
    title = "Cross-Origin Credential Exfiltration Target";
    description = `Form collects sensitive credentials but submits to external domain (${actionHostname}) rather than page origin (${pageHostname}).`;
  } else if (actionIsInsecure && (form.hasPasswordField || form.hasCreditCardField)) {
    severity = "HIGH";
    eventType = "INSECURE_FORM_DETECTED";
    title = "Insecure Unencrypted Credential Submission";
    description = "Form submits authentication credentials over unencrypted HTTP.";
  } else if (form.has2FAField) {
    severity = "MEDIUM";
    eventType = "VERIFICATION_CODE_FORM_DETECTED";
    title = "Two-Factor Verification Code Form";
    description = "Form requests one-time verification passcode (2FA / OTP).";
  } else if (form.hasCreditCardField) {
    severity = "MEDIUM";
    eventType = "PAYMENT_FORM_DETECTED";
    title = "Financial Payment Collection Form";
    description = "Form requests credit card or banking information.";
  } else if (form.hasPasswordField) {
    severity = "LOW";
    eventType = "CREDENTIAL_FORM_DETECTED";
    title = "Authentication Credential Form";
    description = "Form contains password input fields.";
  }
  return {
    id: `form_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
    timestamp: Date.now(),
    tabId: form.tabId,
    pageUrl: form.pageUrl,
    pageOrigin,
    type: eventType,
    severity,
    title,
    description,
    formType,
    actionUrl: form.action,
    actionHostname,
    actionIsCrossOrigin,
    actionIsInsecure,
    hasPasswordField: form.hasPasswordField,
    hasCreditCardField: form.hasCreditCardField,
    has2FAField: form.has2FAField,
    inputCount: form.inputCount,
    hiddenFieldCount: form.hiddenFieldCount,
    evidence: {
      formType,
      actionHostname,
      actionIsCrossOrigin,
      actionIsInsecure,
      hasPasswordField: form.hasPasswordField,
      hasCreditCardField: form.hasCreditCardField,
      has2FAField: form.has2FAField
    }
  };
}
export {
  createFormSecurityEvent
};
