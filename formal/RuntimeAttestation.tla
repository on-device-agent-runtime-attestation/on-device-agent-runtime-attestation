----------------------- MODULE RuntimeAttestation -----------------------
EXTENDS Naturals, Sequences, FiniteSets

CONSTANT MaxSequence

VARIABLES accepted, seen

Records == [
  sequence: 1..MaxSequence,
  nonceMatches: BOOLEAN,
  fresh: BOOLEAN,
  measured: BOOLEAN,
  policyPass: BOOLEAN,
  trustPass: BOOLEAN
]

Init ==
  /\ accepted = <<>>
  /\ seen = {}

CanAccept(record) ==
  /\ record.nonceMatches
  /\ record.fresh
  /\ record.measured
  /\ record.policyPass
  /\ record.trustPass
  /\ record.sequence \notin seen

Accept(record) ==
  /\ record \in Records
  /\ CanAccept(record)
  /\ accepted' = Append(accepted, record)
  /\ seen' = seen \cup {record.sequence}

Reject == UNCHANGED <<accepted, seen>>

Next == (\E record \in Records: Accept(record)) \/ Reject

Spec == Init /\ [][Next]_<<accepted, seen>>

NoReplay == Cardinality(seen) = Len(accepted)
NoStaleAccepted == \A index \in DOMAIN accepted: accepted[index].fresh
NoFailedPredicateAccepted ==
  \A index \in DOMAIN accepted:
    /\ accepted[index].nonceMatches
    /\ accepted[index].fresh
    /\ accepted[index].measured
    /\ accepted[index].policyPass
    /\ accepted[index].trustPass

=============================================================================
