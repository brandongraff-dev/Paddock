export const FAQ: [string, string][] = [
  [
    "Is it legal to run?",
    "Yes, against assets you own or are explicitly authorised to assess. Paddock checks every request against your scope at several layers, asks you to prove control of a domain before it is treated as in scope, and writes every decision to a tamper-evident audit log. Never point it at anything else."
  ],
  [
    "Does it attack or exploit anything?",
    "No. It has no exploit framework, no payload delivery, no credential attacks and no evasion. Dangerous scan categories are blocked in code, and default-credential risk is found by recognising the product, never by trying passwords."
  ],
  [
    "How is this different from a vulnerability scanner?",
    "A scanner hands you a list. Paddock builds a graph of your assets and the weaknesses on them, then walks it to show the paths an attacker could take from the internet to something that matters. Related findings are folded into one ranked story, each with the reason it ranks where it does."
  ],
  [
    "Where does my data go?",
    "Paddock runs on your own infrastructure and keeps findings in your own database. It reaches out only to public data sources (such as certificate logs, DNS and vulnerability feeds) and to services you configure yourself, such as chat, ticketing or an LLM."
  ],
  [
    "Is it ready for production?",
    "It is early. The core pipeline works end to end and has a broad automated test suite, but it has been validated mostly on synthetic data and one live reference host. Run it in the hardened profile, read the security policy, and treat its risk scores as a starting point."
  ],
  [
    "What does it cost?",
    "Self-hosting the Community edition is free under the AGPL-3.0. Paid editions with enterprise features and support are planned."
  ]
];
