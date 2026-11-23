import { isSameSite, parseHttpUrl } from './formDestinations.js';
import { extractDomMetadataFromDocument } from './formMetadata.js';
import { isTrustedFederatedProvider } from '../config/trustedProviders.js';
function evaluateFormSecurity(pageUrl, formMeta) {
  const signals = [];
  if (!formMeta) return signals;
  const page = parseHttpUrl(pageUrl) ?? parseHttpUrl(`https://${pageUrl}`);
  const pageHost = page?.hostname ?? "";
  const submissions = (formMeta.suspiciousForms || []).filter((form) => form.hasPasswordField).flatMap((form) => {
    if (form.hasHttpDestination === false || form.method.toUpperCase() === "DIALOG") return [];
    const destination = parseHttpUrl(form.action, page?.href);
    return destination ? [{ form, destination }] : [];
  });
  if (formMeta.hasPasswordInput) {
    signals.push({
      id: "SIGNAL_PASSWORD_INPUT_PRESENT",
      category: "DOM_SECURITY",
      type: "CREDENTIAL_INPUT_FIELD",
      severity: "LOW",
      weight: 15,
      title: "Credential / Password Entry Field Present",
      description: "The webpage presents a password or credential entry field, indicating an active authentication surface.",
      confidence: 0.95
    });
  }
  if (formMeta.hasCreditCardInput || formMeta.hasSsnInput) {
    signals.push({
      id: "SIGNAL_FINANCIAL_INPUT_PRESENT",
      category: "DOM_SECURITY",
      type: "FINANCIAL_DATA_COLLECTION",
      severity: "MEDIUM",
      weight: 25,
      title: "Payment or Identity Data Input Field Present",
      description: "Page contains input fields explicitly requesting credit card numbers, CVVs, or Social Security numbers.",
      confidence: 0.9
    });
  }
  const insecureForms = submissions.filter(({ destination }) => destination.protocol === "http:");
  if (insecureForms.length > 0) {
    signals.push({
      id: "SIGNAL_INSECURE_FORM_ACTION",
      category: "DOM_SECURITY",
      type: "INSECURE_HTTP_FORM_SUBMISSION",
      severity: "HIGH",
      weight: 40,
      title: "Form Submits Credentials Over Insecure HTTP",
      description: "Form submission endpoint uses unencrypted HTTP protocol. Entered data can be intercepted by network eavesdroppers.",
      confidence: 0.95,
      evidence: { insecureFormsCount: insecureForms.length }
    });
  }
  const rogueCrossOriginForms = submissions.filter(
    ({ destination }) => page && destination.origin !== page.origin && !(destination.protocol === "https:" && isTrustedFederatedProvider(destination.hostname).isTrusted)
  );
  if (rogueCrossOriginForms.length > 0) {
    signals.push({
      id: "CROSS_ORIGIN_CREDENTIAL_HARVESTER",
      category: "DOM_SECURITY",
      type: "CROSS_ORIGIN_CREDENTIAL_HARVESTER",
      severity: "CRITICAL",
      weight: 60,
      title: "Cross-Origin Credential Form Action (Data Drop)",
      description: "The login form submits entered credentials to a different origin. This is a primary signature of credential harvesters.",
      confidence: 0.75,
      evidence: {
        pageHost,
        crossOriginActions: [...new Set(rogueCrossOriginForms.map(({ destination }) => destination.origin))],
        sameSite: rogueCrossOriginForms.every(({ destination }) => isSameSite(page, destination))
      }
    });
  }
  if (submissions.some(({ form }) => form.method.toUpperCase() === "GET")) {
    signals.push({
      id: "SIGNAL_PASSWORD_FORM_GET",
      category: "DOM_SECURITY",
      type: "PASSWORD_FORM_GET_SUBMISSION",
      severity: "MEDIUM",
      weight: 25,
      title: "Password Form Uses GET",
      description: "A GET submission can expose passwords in URLs, history, and logs.",
      confidence: 0.95
    });
  }
  const observed = (formMeta.observedDestinations ?? []).map((value) => parseHttpUrl(value)).filter((destination) => destination && page && (destination.protocol === "http:" || destination.origin !== page.origin && !isTrustedFederatedProvider(destination.hostname).isTrusted));
  if (observed.length) {
    const usesHttp = observed.some((destination) => destination?.protocol === "http:");
    signals.push({
      id: "SIGNAL_POTENTIAL_JS_CREDENTIAL_SUBMISSION",
      category: "DOM_SECURITY",
      type: "POTENTIAL_JS_CREDENTIAL_SUBMISSION",
      severity: usesHttp ? "HIGH" : "MEDIUM",
      weight: usesHttp ? 40 : 35,
      confidence: 0.55,
      title: "Potential JavaScript Credential Submission",
      description: "An asynchronous request used HTTP or targeted an untrusted origin while a password form was present.",
      evidence: { destinations: [...new Set(observed.map((destination) => destination?.origin))] }
    });
  }
  if (formMeta.hasHiddenCredentialFields) {
    signals.push({
      id: "SIGNAL_EXCESSIVE_HIDDEN_FIELDS",
      category: "DOM_SECURITY",
      type: "SUSPICIOUS_HIDDEN_FORM_FIELDS",
      severity: "LOW",
      weight: 12,
      title: "Excessive Hidden State Fields in Auth Form",
      description: "Authentication form includes numerous hidden fields, often utilized by phishing kits to pass stolen session and campaign tracker tags.",
      confidence: 0.7
    });
  }
  if (formMeta.has2FAInput) {
    signals.push({
      id: "SIGNAL_2FA_INTERCEPTION",
      category: "DOM_SECURITY",
      type: "2FA_OTP_INTERCEPTION_FIELD",
      severity: "MEDIUM",
      weight: 20,
      title: "Two-Factor / Passcode Request Field",
      description: "Page requests OTP authentication tokens, 2FA codes, or cryptocurrency seed phrases.",
      confidence: 0.85
    });
  }
  return signals;
}
export {
  evaluateFormSecurity,
  extractDomMetadataFromDocument
};
