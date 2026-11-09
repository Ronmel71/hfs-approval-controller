import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const source = readFileSync(new URL('../.github/workflows/connectivity-only-review.yml', import.meta.url), 'utf8');

test('approval workflow is manual, first-attempt and main-only', () => {
  assert.match(source, /\non:\n  workflow_dispatch:\n/);
  assert.doesNotMatch(source, /^  (push|pull_request|pull_request_target|workflow_run|schedule|repository_dispatch):/m);
  assert.equal(source.match(/github\.run_attempt == 1/g)?.length, 2);
  assert.equal(source.match(/github\.ref == 'refs\/heads\/main'/g)?.length, 2);
});
test('only opaque request hashes can reach the protected review', () => {
  assert.equal(source.match(/\[\[ "\$REQUEST_ID" =~ \^\[0-9a-f\]\{64\}\$ \]\]/g)?.length, 2);
  assert.match(source, /needs: validate/);
  assert.match(source, /needs\.validate\.result == 'success'/);
  assert.match(source, /environment: production-first-start/);
  assert.match(source, /run-name: Connectivity-only approval · \$\{\{ inputs.request_id \}\}/);
});
test('approval has no secret, signing, checkout, artifact, server, or write path', () => {
  assert.match(source, /permissions:\n  contents: read\n/);
  assert.doesNotMatch(source, /secrets\.|uses:|actions: write|contents: write|id-token:|curl\b|ssh\b|sudo\b|node\b|INSTALL_ONLY_GO|START_GO/);
  assert.match(source, /CONNECTIVITY_ONLY_APPROVAL_RECORDED/);
  assert.match(source, /cancel-in-progress: false/);
});
