# Sentence-final version boundary

The second deployment at `0xbF3b79eB2550f6265CC979e46b1096557a3B337A` reached majority
agreement for the branches and pre-release cases. The unclear-prerequisite case
ended UNDETERMINED / MAJORITY_DISAGREE. All four leader rounds reported
`Version boundary lacks an exact anchor`.

The source writes the upper version at the end of a sentence: `2.4.7.`. The token
guard incorrectly rejected that sentence punctuation along with dotted version
suffixes. The final guard permits a period followed by whitespace or end of text,
while still rejecting `.1`, pre-release and build suffixes. Four regression tests
cover those distinct cases. No consensus or semantic checks were relaxed.
