"""paddock SCA (Software Composition Analysis) service.

Extracts the dependency graph (SBOM) from a build's lockfiles, matches the
components against OSV.dev, and flags the supply-chain *risk the owner is
exposed to* (vulnerable deps, dependency-confusion exposure, possible
typosquats, abandoned/yanked/malicious packages, unpinned ranges).

INVARIANT (defensive, detection-only). This service finds where the owner is
EXPOSED to supply-chain attacks. It MUST NOT, under any circumstances:
  * search for dependency combinations that defeat or evade controls;
  * build, craft, or suggest malicious / typosquatting / confusion packages;
  * publish, register, or claim any package name on any registry;
  * execute, import, evaluate, or otherwise run any parsed lockfile or the
    code it references -- lockfiles are untrusted DATA, parsed as text only.
The only outbound traffic is to OSV.dev and public package-registry metadata
APIs. Anything offensive is out of scope; if such code appears here, delete it.
"""

__version__ = "0.1.0"
