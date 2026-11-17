---- MODULE FileWritePilot ----
\* Abstract model of one file-write operation under the Nova pilot.
\* Attempts are created, claimed, publish the target, crash, and finish. A competing writer
\* may take the target path while it is still empty (the link race). The model checks the
\* safety properties in docs/security/FILE_WRITE_PILOT.md against every interleaving.
EXTENDS Naturals, TLC

CONSTANTS MaxAttempts, Expected, Other, None

VARIABLES st,       \* attempt states, indexed 1..MaxAttempts
          owner,    \* index of the attempt that published the target, 0 if none
          crashed,  \* crashed[i]: the worker for attempt i died after claiming
          target,   \* None, Expected, or Other
          n         \* attempts created so far

vars == <<st, owner, crashed, target, n>>

Idx == 1..MaxAttempts
Live == {"NOT_EXECUTED", "CLAIMED", "UNKNOWN", "SUCCEEDED"}

Init ==
    /\ st = [i \in Idx |-> "UNUSED"]
    /\ owner = 0
    /\ crashed = [i \in Idx |-> FALSE]
    /\ target = None
    /\ n = 0

Create ==
    /\ n < MaxAttempts
    /\ \A i \in Idx : st[i] \notin {"CLAIMED", "UNKNOWN", "SUCCEEDED"}
    /\ st' = [st EXCEPT ![n + 1] = "NOT_EXECUTED"]
    /\ n' = n + 1
    /\ UNCHANGED <<owner, crashed, target>>

Claim(i) ==
    /\ st[i] = "NOT_EXECUTED"
    /\ \A j \in Idx : st[j] /= "CLAIMED"
    /\ st' = [st EXCEPT ![i] = "CLAIMED"]
    /\ UNCHANGED <<owner, crashed, target, n>>

\* Stage then link. The link succeeds only when the target is empty.
Publish(i) ==
    /\ st[i] = "CLAIMED"
    /\ target = None
    /\ owner = 0
    /\ target' = Expected
    /\ owner' = i
    /\ UNCHANGED <<st, crashed, n>>

\* Finish the claimed attempt from whatever the target now holds.
Finish(i) ==
    /\ st[i] = "CLAIMED"
    /\ LET recovering == crashed[i] IN
       \/ /\ target = Expected /\ owner = i
          /\ st' = [st EXCEPT ![i] = "SUCCEEDED"]
       \/ /\ target = Expected /\ owner /= i
          /\ st' = [st EXCEPT ![i] = IF recovering THEN "SUCCEEDED" ELSE "FAILED"]
       \/ /\ target = Other
          /\ st' = [st EXCEPT ![i] = IF recovering THEN "UNKNOWN" ELSE "FAILED"]
       \/ /\ target = None
          /\ st' = [st EXCEPT ![i] = "FAILED"]
    /\ UNCHANGED <<owner, crashed, target, n>>

Crash(i) ==
    /\ st[i] = "CLAIMED"
    /\ ~crashed[i]
    /\ crashed' = [crashed EXCEPT ![i] = TRUE]
    /\ UNCHANGED <<st, owner, target, n>>

\* A competing writer creates the target, but only while it is still empty.
Adversary ==
    /\ target = None
    /\ \E v \in {Expected, Other} : target' = v
    /\ UNCHANGED <<st, owner, crashed, n>>

Next ==
    \/ Create
    \/ \E i \in Idx : Claim(i) \/ Publish(i) \/ Finish(i) \/ Crash(i)
    \/ Adversary

Spec == Init /\ [][Next]_vars

\* ---------------------------------------------------------------- safety

AtMostOneLive ==
    \A i, j \in Idx : (i /= j) => ~(st[i] \in Live /\ st[j] \in Live)

AtMostOneSucceeded ==
    \A i, j \in Idx : (i /= j) => ~(st[i] = "SUCCEEDED" /\ st[j] = "SUCCEEDED")

SucceededNeedsExpectedBytes ==
    \A i \in Idx : st[i] = "SUCCEEDED" => target = Expected

\* The attempt that published never ends FAILED: the effect exists, so the outcome is not failure.
PublisherNeverFails ==
    \A i \in Idx : (owner = i) => st[i] /= "FAILED"

\* A fresh (non-crashed) attempt succeeds only for bytes it published. This is the race bug.
SucceededOnlyIfOwnedOrRecovered ==
    \A i \in Idx : st[i] = "SUCCEEDED" => (owner = i \/ crashed[i])

====
