import { parseHttpUrl } from './formDestinations.js';
function extractDomMetadataFromDocument(doc, pageUrl, query = (selector) => doc.querySelectorAll(selector), includeExternalScripts = true) {
  const passwordInputs = Array.from(query('input[type="password"]'));
  const hasPasswordInput = passwordInputs.length > 0;
  const emailOrUserInputs = Array.from(query(
    'input[type="email"], input[name*="user" i], input[name*="login" i], input[id*="user" i], input[id*="login" i], input[autocomplete="username"], input[autocomplete="email"]'
  ));
  
const hasEmailOrUserInput = emailOrUserInputs.length > 0;
  
const ccInputs = Array.from(query([
  'input[autocomplete^="cc-" i]',
  'input[name*="cardnumber" i]',
  'input[name*="card_number" i]',
  'input[name*="card-number" i]',
  'input[name*="creditcard" i]',
  'input[name*="credit_card" i]',
  'input[name*="cc-number" i]',
  'input[name*="cc_number" i]',
  'input[name*="cvv" i]',
  'input[name*="cvc" i]',
  'input[id*="cardnumber" i]',
  'input[id*="card_number" i]',
  'input[id*="card-number" i]',
  'input[id*="cvv" i]',
  'input[id*="cvc" i]'
].join(", ")));

const hasCreditCardInput = ccInputs.length > 0;

const ssnInputs = Array.from(query([
  'input[name="ssn" i]',
  'input[id="ssn" i]',
  'input[name*="social_security" i]',
  'input[id*="social_security" i]',
  'input[name*="social-security" i]',
  'input[id*="social-security" i]',
  'input[autocomplete="off"][name*="ssn" i]'
].join(", ")));

const hasSsnInput = ssnInputs.length > 0;

  
const twoFaInputs = Array.from(query([
  'autocomplete~="one-time-code"',
  'name*="otp"',
  'name*="2fa"',
  'id*="otp"',
  'id*="2fa"',
  'name*="one_time_code"',
  'name*="verification_code"'
].map((attribute) =>
  `input:not([type="hidden" i])[${attribute} i]`
).join(", ")));

  const forms = Array.from(query("form"));
  const page = parseHttpUrl(pageUrl);
  const base = doc.URL === "about:blank" ? parseHttpUrl(doc.querySelector("base[href]")?.getAttribute("href") ?? "", pageUrl)?.href : doc.baseURI;
  let hasHiddenCredentialFields = false;
  const suspiciousForms = forms.flatMap((form) => {
    const controls = Array.from(form.elements);
    const inputs = controls.filter((control) => control.tagName === "INPUT");
    const hasPasswordField = inputs.some((input) => input.type === "password");
    const hiddenInputsCount = inputs.filter((input) => input.type === "hidden").length;
    hasHiddenCredentialFields ||= hasPasswordField && hiddenInputsCount > 5;
    const destinations = [{
      action: form.getAttribute("action"),
      method: form.method.toUpperCase()
    }];
    for (const control of controls) {
      const submitter = control;
      if ((submitter.type === "submit" || submitter.type === "image") && (submitter.hasAttribute("formaction") || submitter.hasAttribute("formmethod"))) {
        destinations.push({
          action: submitter.getAttribute("formaction") ?? destinations[0].action,
          method: submitter.hasAttribute("formmethod") ? submitter.formMethod.toUpperCase() : destinations[0].method
        });
      }
    }
    const entries = destinations.map(({ action, method }) => {
      const destination = method === "DIALOG" ? null : action?.trim() ? parseHttpUrl(action, base) : page;
      return {
        action: destination?.origin ?? "",
        method,
        isCrossOrigin: !!page && !!destination && page.origin !== destination.origin,
        isInsecureHttp: destination?.protocol === "http:",
        hasPasswordField,
        inputCount: controls.filter((control) => control.matches("input, select, textarea")).length,
        hiddenInputsCount,
        hasHttpDestination: !!destination
      };
    });
    return [...new Map(entries.map((entry) => [JSON.stringify(entry), entry])).values()];
  });
 
const externalScripts = [];

try {
  const scriptTags = includeExternalScripts
    ? Array.from(query("script[src]"))
    : [];

  for (const script of scriptTags.slice(0, 10)) {
    const src = script.getAttribute("src");

    if (!src) continue;

    const scriptUrl = parseHttpUrl(
      src,
      doc.baseURI || pageUrl
    );

    if (scriptUrl) {
      externalScripts.push(scriptUrl.href);
    }
  }
} catch {
  // Ignore invalid script metadata
}

  return {
    hasPasswordInput,
    hasCreditCardInput,
    hasSsnInput,
    hasEmailOrUserInput,
    has2FAInput: twoFaInputs.length > 0,
    formsCount: forms.length,
    suspiciousForms,
    hasHiddenCredentialFields,
    hasExternalScriptSources: externalScripts,
    pageTitle: doc.title
  };
}
export {
  extractDomMetadataFromDocument
};
