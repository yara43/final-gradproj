
import assert from 'node:assert/strict';
import { evaluateFormSecurity } from './extension/engine/formAnalysis.js';

const pageUrl = 'https://example.com/login';

const baseMeta = {
    hasPasswordInput: false,
    hasCreditCardInput: false,
    hasSsnInput: false,
    hasEmailOrUserInput: false,
    has2FAInput: false,
    hasHiddenCredentialFields: false,
    formsCount: 0,
    suspiciousForms: [],
    observedDestinations: [],
    hasExternalScriptSources: []
};

const baseForm = {
    action: 'https://example.com',
    method: 'POST',
    hasPasswordField: true,
    isCrossOrigin: false,
    isInsecureHttp: false,
    hasHttpDestination: true,
    inputCount: 2,
    hiddenInputsCount: 0
};

const passwordMeta = {
    hasPasswordInput: true,
    formsCount: 1,
    suspiciousForms: [baseForm]
};

const P = 'SIGNAL_PASSWORD_INPUT_PRESENT';
const F = 'SIGNAL_FINANCIAL_INPUT_PRESENT';
const H = 'SIGNAL_INSECURE_FORM_ACTION';
const C = 'CROSS_ORIGIN_CREDENTIAL_HARVESTER';
const G = 'SIGNAL_PASSWORD_FORM_GET';
const O = 'SIGNAL_2FA_INTERCEPTION';
const E = 'SIGNAL_EXCESSIVE_HIDDEN_FIELDS';
const J = 'SIGNAL_POTENTIAL_JS_CREDENTIAL_SUBMISSION';

const tests = [
    {
        name: 'Normal page without forms',
        meta: {},
        expected: []
    },
    {
        name: 'Secure password form',
        meta: passwordMeta,
        expected: [P]
    },
    {
        name: 'Credit card detection',
        meta: { hasCreditCardInput: true },
        expected: [F]
    },
    {
        name: 'SSN detection',
        meta: { hasSsnInput: true },
        expected: [F]
    },
    {
        name: 'OTP detection',
        meta: { has2FAInput: true },
        expected: [O]
    },
    {
        name: 'Insecure HTTP submission',
        meta: {
            ...passwordMeta,
            suspiciousForms: [{
                ...baseForm,
                action: 'http://example.com',
                isCrossOrigin: true,
                isInsecureHttp: true
            }]
        },
        expected: [P, H, C]
    },
    {
        name: 'Cross-origin credential submission',
        meta: {
            ...passwordMeta,
            suspiciousForms: [{
                ...baseForm,
                action: 'https://external.invalid',
                isCrossOrigin: true
            }]
        },
        expected: [P, C]
    },
    {
        name: 'Password submission using GET',
        meta: {
            ...passwordMeta,
            suspiciousForms: [{
                ...baseForm,
                method: 'GET'
            }]
        },
        expected: [P, G]
    },
    {
        name: 'Excessive hidden fields',
        meta: {
            ...passwordMeta,
            hasHiddenCredentialFields: true
        },
        expected: [P, E]
    },
    {
        name: 'Potential JavaScript submission',
        meta: {
            ...passwordMeta,
            observedDestinations: [
                'https://external.invalid'
            ]
        },
        expected: [P, J]
    },
    {
        name: 'Same-origin JavaScript request',
        meta: {
            ...passwordMeta,
            observedDestinations: [
                'https://example.com'
            ]
        },
        expected: [P]
    },
    {
        name: 'Cross-origin form without password',
        meta: {
            formsCount: 1,
            suspiciousForms: [{
                ...baseForm,
                action: 'https://external.invalid',
                hasPasswordField: false,
                isCrossOrigin: true
            }]
        },
        expected: []
    },
    {
        name: 'Dialog form without HTTP submission',
        meta: {
            ...passwordMeta,
            suspiciousForms: [{
                ...baseForm,
                method: 'DIALOG',
                hasHttpDestination: false
            }]
        },
        expected: [P]
    },
    {
        name: 'Multiple sensitive input types',
        meta: {
            ...passwordMeta,
            hasCreditCardInput: true,
            hasSsnInput: true,
            has2FAInput: true
        },
        expected: [P, F, O]
    }
];

let passed = 0;
let failed = 0;

console.log('\n========================================');
console.log(' PHISHGUARD - FORM INSPECTION TESTS');
console.log('========================================\n');

for (const test of tests) {
    try {
        const metadata = {
            ...baseMeta,
            ...test.meta
        };

        const signals = evaluateFormSecurity(
            pageUrl,
            metadata
        );

        const actual = signals.map(
            signal => signal.id
        ).sort();

        const expected = [...test.expected].sort();

        assert.deepEqual(actual, expected);

        console.log(`[PASS] ${test.name}`);
        passed++;
    } catch (error) {
        console.log(`[FAIL] ${test.name}`);
        console.log(error.message);
        failed++;
    }
}

console.log('\n========================================');
console.log(`Total Tests : ${tests.length}`);
console.log(`Passed      : ${passed}`);
console.log(`Failed      : ${failed}`);
console.log(
    `Pass Rate   : ${(passed / tests.length * 100).toFixed(2)}%`
);
console.log('========================================\n');

process.exitCode = failed > 0 ? 1 : 0;
