# Demo Script

A discovery-call-style walkthrough for presenting SOC Navigator — useful both as a portfolio demo
and as a template for how I'd actually run a technical discovery conversation with a SOC lead.

## Discovery questions

Before showing anything, these are the questions I'd want answered in a real deal:

1. How many alerts does your team investigate on an average day?
2. What percentage of those require manual analyst investigation vs. auto-resolution?
3. How do analysts currently determine which alerts are related to the same incident?
4. What's your average time from alert to triaged investigation?
5. Where do analysts lose the most time — data gathering, correlation, or write-up?
6. How are incidents currently communicated up to leadership, and how technical is that audience?
7. How much ongoing tuning does your team do to keep false-positive rates manageable?

## Demo flow

1. **Start at Overview.** "This is what a day looks like before triage: alerts generated, how many
   cleared the confidence threshold as signals, how many are open incidents right now."
2. **Open Attack Lab and run the account-compromise scenario.** Watch raw telemetry collapse live
   into one correlated critical incident, then click Investigate.
3. **Open the incident, Analyst View, Detection tab.** Show the matched rule, the raw Sigma YAML,
   and the specific confidence factors (unknown parent process, network connection,
   first-seen-for-user) that pushed confidence to 97% — then the Timeline and ATT&CK tabs for the
   full kill chain.
4. **Switch to Security Leader View on the same incident.** Same underlying data, translated:
   business risk, recommended priority, current status — no technique IDs.
5. **Run the false-positive scenario.** Same detection signature as step 3, different context (IT
   admin, approved maintenance window, known script) → reviewed and closed as benign at ~3%
   confidence. This is the "reducing operational noise" conversation made concrete.
6. **Ask the AI assistant a question live** — "why is this critical?" or "what should I investigate
   next?" — to show the assistant explaining and prioritizing, not re-deciding the verdict.

## Business outcome framing

- Reduce analyst investigation effort by correlating related alerts before a human ever opens them
- Reduce operational noise by scoring confidence from context, not just signature match
- Accelerate incident understanding with an auditable "why did we alert" trail instead of a raw
  alert dump
- Improve executive communication with a business-risk view generated from the same data an
  analyst is already looking at, not a separate report written after the fact
