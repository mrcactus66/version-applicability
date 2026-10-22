# Earlier deployment

These receipts belong to the first deployment at
`0x78Cbc71C3EC3e7FC8D3A66439cBfA19F4Ff04459`, before source-witness normalization.
They are not evidence for the final contract.

The branches review ended UNDETERMINED / NO_MAJORITY after three rotations.
An earlier leader failed with `Range quote must occur verbatim`; the final leader
returned the expected two version intervals and four scope decisions, but did
not reach the required agreement. The final validators' independent extractions
are not present in the compact receipt, so not every disagreement is attributable
to quote formatting.

The revised contract resolves whitespace-only reflow back to an exact contiguous
source span before checking and storing witnesses. It does not permit changes to
words, punctuation, version endpoints or deployment decisions. Two regression
tests cover restored formatting and rejection of changed source text.

All advisories and inventory records are synthetic. The deployment transaction
was recovered from Studio Explorer account history after its EVM receipt read
failed; the original deployment was not repeated to recover that transaction.

## RPC discovery fallback

`fallback-unclear-review-transaction.json` records a later zero-value transaction
on the final deployment's account. Its receipt is FINALIZED / NO_MAJORITY, type 0,
with no consensus executions and no Intelligent Contract calldata. Its recipient
is the SDK's baked-in old ConsensusMain address, not the intended contract. A read
of the registered policy succeeded; the corresponding review read failed with
RPC error -32000 (`execution failed`). No review result was created by that call.

The SDK catches a failed `sim_getConsensusContract` request and can retain its
static configuration. The reproduction script now retries that read with a bound
and refuses to proceed unless live consensus-address discovery succeeded. The
failed transaction remains here rather than being counted among the seven
successful final demonstration transactions.
