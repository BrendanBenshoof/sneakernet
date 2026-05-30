# Ethics of Sneakernet

## Mutual Support as Premise

I have spent many years working in what people call big tech. The people I met there were, in general, kind and genuinely concerned about the world. They also mostly did not understand how close to the edge of survival most people on this planet are kept. My life gave me a broader view — poor people as peers, rich ones too. What I kept finding was that the most valuable thing you can do is simply let people talk to each other. Across social, economic, and national boundaries. To find out that the people over there are just people. That is where empathy starts. That is the root of mutual aid.

Sneakernet is my contribution to that, as a tool builder. Some version of this design has been in my head for over a decade. The premise is both simple and complex: robust, low-bandwidth communication, available everywhere, that scales from a single local community up to the whole world and back down again.

There is no reward infrastructure here. No incentives beyond wanting people to be able to hear each other. That keeps this project small, probably permanently. That is fine. The goal is that everyone has at least some access to the voices of everyone else — across the tribal and political boundaries that make that hard. Anonymity and broad message propagation are not ideological choices; they are requirements for that to actually work in a polarized world.

This only functions because people run it for each other. There is nowhere to put a meter — no accounts, no addressing, no data to harvest. It cannot be monetized by design, which means it cannot be a product, which means it can only exist as a community collaboration. That collaboration extends by default to people you don't know and people you don't agree with. That is the premise. Everything else follows from it.

---

## Why Communication Matters

Communication should work. Not fast, not rich, not always — but people should be able to reach each other. The constraint on that should be physics and logistics, not politics, economics, or the preferences of a platform.

The normal internet fails this constantly. It fails under surveillance. It fails when a government decides to shut it down. It fails when a hurricane takes out the infrastructure. It fails in rural areas that were never worth the investment to wire up properly. It fails when the economy collapses and people can't afford access. It fails at borders. It fails for people whose existence a platform has decided is a terms-of-service violation.

These are not edge cases. For most of the world, one or more of these is just the condition of life.

Sneakernet is not targeted at any specific adversary or any specific community. It is built for the gap — wherever infrastructure fails or is hostile, for whatever reason.

---

## What This Is Relative to Everything Else

Sneakernet is not a replacement for anything. Signal is excellent. Email works. SMS reaches almost every phone on the planet. Radio crosses distances that nothing else can without infrastructure. Use all of them. This is not a competition.

Every one of those systems has a boundary where it stops working.

Signal requires a phone number, an internet connection, and servers that stay up. It is the right tool until the network goes down or the account gets deactivated.

Email is ubiquitous and persistent, but it runs through servers owned by someone else, in jurisdictions with their own legal appetites. It is surveilled at rest and in transit by default.

SMS works on weak signals and reaches hardware that nothing else does. It also runs entirely through carrier infrastructure that is trivially accessible to state actors and fails completely when cell towers go down.

Radio needs no internet and no carrier. It crosses borders and disasters without asking permission. It is also heavily regulated in most of the world, broadcast-only in its accessible forms, and offers no privacy whatsoever.

Sneakernet occupies the space those systems leave. Low bandwidth, high latency, no central infrastructure, no surveillance surface. It does not replace any of them — it ties them together and keeps working in the gaps between them. A message can start on a phone, move through a local relay, cross an air gap on a USB drive, and arrive somewhere the internet never reached. The transport doesn't matter. The message moves.

---

## Risks and Mitigations

Anonymous p2p communication systems have a reputation as refuges for illegal and immoral activity. Sneakernet will be used for some of those things. That is not a surprise and it is not deniable.

The design does not try to be a moral filter. It has a goal: let people have conversations across the boundaries that normally prevent that. The most common and serious forms of abuse that plague anonymous networks — image-based exploitation, large-scale piracy, bulk harassment campaigns — require things this system cannot do well. Not because it is trying to prevent them, but because it is trying to do something else. Two pages of text per message. Proof-of-work that makes flooding economically unviable. No accounts, no metadata, no amplification mechanism. The abuse ceiling is a byproduct of the goal, not a separate policy imposed on top of it.

What remains is the irreducible risk of any communication tool: people will use it to say things to each other that are harmful. Operators have some structural control — they choose their peers, set their PoW floors, and can decline to sync with relays they distrust — without being able to read content. The network's natural partitioning means there is no platform-scale vector for harm to propagate. But there is no complete mitigation. A tool that lets people talk lets people say bad things.

Running a relay creates legal risk in many jurisdictions. The design minimizes what operators hold: opaque ciphertext, a content-addressed ID, a PoW stamp, an arrival timestamp. No user registry, no message headers, no sender or recipient fields. An operator compelled to hand over their block store is handing over something they are already giving freely to anyone who asks — that is how the protocol works. The compulsion is largely pointless. Log minimally regardless. The less connection metadata you hold the less can be taken.

PoW requires CPU time and energy. That cost is real and worth naming. The Argon2id memory-hardness requirement is intentionally CPU-bound, which disadvantages the GPU and ASIC parallelism responsible for most cryptocurrency energy consumption. Each block is a single computation, not an ongoing competition. The energy cost is closer to sending an email than to anything blockchain-adjacent.

---

## Censorship and Consent

Consensual moderation is good. Communities that agree to shared standards, curated spaces, filters that members opt into — these are healthy and worth building. There is nothing wrong with a community choosing what it wants to talk about and how.

The problem is when moderation becomes invisible and unavoidable. When the curtain is there but you cannot look behind it. When the only version of a conversation you can access is already filtered, and you have no way to know what is missing.

Sneakernet channels are, at present, unmoderatable public forums. There are no consequences built in, no authority to appeal to, no mechanism to suppress a message once it is in the network. That is the foundation — a layer that exists underneath whatever moderated spaces get built on top of it, one that anyone can access without fear. The ability to see behind the curtain and the ability to audit what the curtain is hiding are the same thing.

This also means we have a responsibility to educate users before handing them this tool. An unmoderated public forum without consequences is not a comfortable space. People will say things there that are harmful, false, and ugly. Putting someone into that environment without preparing them for it is a failure on our part, not a surprise they should absorb on their own.

Consensual moderation mechanisms — ways for communities to agree to filters that apply only to those who want them, while leaving the underlying layer intact and auditable — are the next focus as this project matures. The goal is spaces where moderation is real, consent is real, and the option to look behind the curtain is always there.

---

## What This Will Not Fix

Sneakernet cannot offer forward secrecy. A compromised key exposes every message ever encrypted to it. That is not a flaw that can be patched — it is a consequence of the store-and-forward model, where messages persist across nodes for days or weeks before being read.

Key management is already the most broadly misunderstood part of applied cryptography. Most people who use encrypted communication tools have no mental model of what a key is, what losing it means, or what happens when someone else gets it. That gap exists before Sneakernet. Deploying this broadly makes it matter more.

Those of us who understand this have a responsibility to teach it. Not as a disclaimer buried in documentation, but as a genuine obligation that comes with putting cryptographic tools in front of people who haven't asked to become cryptographers. We must.
