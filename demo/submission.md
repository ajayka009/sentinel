# Submission draft — Meta Global AI Developer Hackathon, Indie Track

Fill into the submission form. Deadline: **Tue Nov 4, 9:00 PM ET**.

## Basics

- **Project:** Sentinel — an agent-aware firewall for edge, IoT, and physical AI.
- **Theme:** Push the Frontier (models meeting the real world: physical
  systems, manufacturing). Secondary: Build for Your World (the OT/edge
  world the builder knows firsthand).
- **Track:** Indie developer (solo).
- **Repo:** <TODO: public repo URL>
- **Demo video (3 min):** <TODO: video URL, recorded from `demo/script.md`>

## Pitch (one paragraph)

Today's firewalls filter packets, not agents. As AI agents start operating
physical systems at the edge — PLCs, sensors, yard equipment — there is no
firewall built for them: no identity-aware policy, no attack-surface map of
what an agent can reach, no prevention loop that revokes a rogue agent in
real time. Sentinel is an agentic framework that digests an edge/IoT
environment, maps its attack surface, builds a dynamic firewall from business
rules stated in plain language, and enforces it live — blocking, quarantining,
and revoking rogue agents before they touch physical equipment.

Positioning: "Traditional firewalls inspect packets; Sentinel inspects
intent." Closing: "Packets get filtered. Agents get governed."

## Models used

Spark 1.3 (digest, policy compiler), Wonder (attack-surface analysis),
SAM 3.1 (camera segmentation), Muse Image (synthetic frames). Runtime
enforcement is deterministic code — zero model calls in the loop
(models advise, code decides).

## Judging coverage

- **Creativity:** an agent-aware firewall — identity-aware policy,
  attack-surface mapping, and live revocation; no packet filter does this.
- **Technical ambition:** a framework plus a working two-site simulator plus
  five layers (digest, analyst, policy compiler, enforcement, console).
- **Works:** scripted attacks blocked live on video and reproducible on any
  localhost with no API key (`Try it yourself` in the README).

## Pre-submit checklist

- [ ] Repo public with complete README (pitch, architecture diagram with the
  adjacent network-firewall layer below Sentinel, run instructions).
- [ ] 3-minute demo video follows `demo/script.md` (console screen capture
  + narration).
- [ ] Form: theme = Push the Frontier; track = Indie; models listed above.
- [ ] Clean end-to-end run: sim up, console up, Red team attacks all
  blocked, `python3 -m unittest discover -s tests` green.
- [ ] No real credentials, employer data, or personal data in repo or video.
  Synthetic demo data only. (`.env` is gitignored; key lives only there.)
