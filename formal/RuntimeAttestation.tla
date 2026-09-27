----------------------- MODULE RuntimeAttestation -----------------------
EXTENDS Naturals, Sequences, FiniteSets

CONSTANT MaxSequence

VARIABLES accepted, seenSequences, usedNonces

Outcome == {"untrusted", "degraded", "trusted"}
Rank(outcome) == IF outcome = "trusted" THEN 2 ELSE IF outcome = "degraded" THEN 1 ELSE 0

Records == [
  sequence: 1..MaxSequence,
  nonce: 1..MaxSequence,
  nonceIssued: BOOLEAN,
  fresh: BOOLEAN,
  signatureValid: BOOLEAN,
  eventLogValid: BOOLEAN,
  goldenRank: 0..2,
  outcome: Outcome,
  toolAllowed: BOOLEAN
]

Init ==
  /\ accepted = <<>>
  /\ seenSequences = {}
  /\ usedNonces = {}

ComputedOutcome(record) ==
  IF record.goldenRank = 2 THEN "trusted" ELSE IF record.goldenRank = 1 THEN "degraded" ELSE "untrusted"

CanAccept(record) ==
  /\ record.nonceIssued
  /\ record.fresh
  /\ record.signatureValid
  /\ record.eventLogValid
  /\ record.sequence \notin seenSequences
  /\ record.nonce \notin usedNonces
  /\ record.outcome = ComputedOutcome(record)
  /\ record.outcome # "untrusted"
  /\ record.toolAllowed

Accept(record) ==
  /\ record \in Records
  /\ CanAccept(record)
  /\ accepted' = Append(accepted, record)
  /\ seenSequences' = seenSequences \cup {record.sequence}
  /\ usedNonces' = usedNonces \cup {record.nonce}

Reject == UNCHANGED <<accepted, seenSequences, usedNonces>>

Next == (\E record \in Records: Accept(record)) \/ Reject

Spec == Init /\ [][Next]_<<accepted, seenSequences, usedNonces>>

NoReplayAccepted ==
  /\ Cardinality(seenSequences) = Len(accepted)
  /\ Cardinality(usedNonces) = Len(accepted)

NoStaleQuoteAccepted ==
  \A index \in DOMAIN accepted:
    /\ accepted[index].fresh
    /\ accepted[index].nonceIssued

NoReorderedQuoteAccepted ==
  \A left, right \in DOMAIN accepted:
    left < right => accepted[left].sequence # accepted[right].sequence

AppraisalMonotonicity ==
  \A index \in DOMAIN accepted:
    Rank(accepted[index].outcome) <= accepted[index].goldenRank

NoInvalidEventLogAccepted ==
  \A index \in DOMAIN accepted: accepted[index].eventLogValid

=============================================================================
