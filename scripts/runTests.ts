import { runSecurityTestSuite } from '../src/core/tests/testSuite';

async function main() {
  console.log('🧪 Running PhishGuard Multi-Scenario Behavioral Test Suite...');
  const outcome = await runSecurityTestSuite();

  console.log('\n======================================================');
  console.log(`TEST SUITE RESULTS: ${outcome.passed}/${outcome.total} Passed (${outcome.passRate}%) in ${outcome.totalTimeMs}ms`);
  console.log('======================================================\n');

  for (const r of outcome.results) {
    const mark = r.passed ? '✓ PASS' : '✗ FAIL';
    console.log(`${mark} | ${r.testName}`);
    console.log(`       Verdict: ${r.actualVerdict} (Expected: ${r.expectedVerdict}), Score: ${r.actualScore} [${r.expectedMinScore}-${r.expectedMaxScore}]`);
    if (!r.passed && r.failureReason) {
      console.log(`       Failure: ${r.failureReason}`);
    }
  }

  if (outcome.failed > 0) {
    process.exit(1);
  }
}

main().catch(err => {
  console.error('Test execution error:', err);
  process.exit(1);
});
