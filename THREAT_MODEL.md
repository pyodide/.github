# Pyodide Threat Model

This document describes what Pyodide protects, who we consider an attacker, and which risks we accept. It focuses on the Pyodide runtime (`pyodide`), the build tooling (`pyodide-build`, `auditwheel-emscripten`) and `micropip`.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## 1. Summary

- Pyodide runs Python compiled to WebAssembly inside a JavaScript engine (a browser or Node.js). The host's sandbox is the primary isolation boundary. Pyodide does not add a second one.
- Arbitrary Python execution inside Pyodide is a feature. By itself it is **not** a vulnerability, because the code has only the privileges of the embedding JavaScript context.
- Our main concern is the **supply chain**: the code and artifacts that users load into their runtime, and the tools that produce them. A compromise there runs attacker code with the privileges of the embedding application, for example its origin, cookies and tokens.
- Building packages with `pyodide-build` runs third-party build code on the **host machine**, outside any WebAssembly sandbox. This is the highest-impact risk for maintainers and CI.

## 2. Assets

| Asset | Why it matters |
| --- | --- |
| Integrity of runtime artifacts (`pyodide.js`, `pyodide.asm.wasm`, package wheels) | Anything loaded into the user's page executes with that page's privileges |
| Release channels (PyPI, npm, GitHub Releases, CDN) | These are how artifacts reach users |
| Maintainer and CI credentials | They allow publishing and altering artifacts |
| Host machines and CI runners that build packages | They execute untrusted build code |
| Embedding application data (origin, storage, tokens) | This is what an attacker gains through a compromised runtime or package |

## 3. Trust boundaries and assumptions

1. **Browser or Node.js sandbox.** In browsers, Pyodide inherits the same-origin policy and the JS engine's WebAssembly sandbox. We assume these hold and treat their bugs as out of scope.
2. **Node.js is weaker.** Node.js does not sandbox WebAssembly from the host process. Python code running in Pyodide under Node can use Node APIs through the JS bridge. Untrusted code must not run in Pyodide under Node without an additional OS-level sandbox.
3. **Python and JavaScript share one trust domain.** Python code can call JavaScript, and the reverse. Embedding applications that run untrusted Python in the same page as sensitive data are responsible for isolating it, for example with an iframe or a Web Worker on a separate origin.
4. **Package indexes.** PyPI, the npm registry and the CDN are trusted to serve what maintainers published, within the limits described in §5.

## 4. Attackers

| Attacker | Capability |
| --- | --- |
| Author of untrusted Python code run in Pyodide | Limited to the host sandbox. Largely out of scope (§7) |
| Malicious upstream package author or a compromised upstream maintainer account | Publishes malicious code on PyPI or npm that we build or users install |
| Malicious contributor | Submits a malicious patch or workflow change |
| CDN, registry or network attacker | Replaces or tampers with artifacts in transit or at rest |
| Compromised maintainer or CI credential | Publishes or alters releases |

## 5. Supply chain threats

### 5.1 Building packages with `pyodide-build`

Building a package runs upstream `setup.py` or PEP 517 build backends, and arbitrary build requirements. All of this runs on the host, not in WebAssembly.

| Threat | Current state | Residual risk |
| --- | --- | --- |
| Upstream build code is malicious | Not sandboxed. `pyodide build` uses pypa/build isolation by default (a venv, not a security boundary) and offers a `no_isolation` option | A compromised upstream release runs arbitrary code on the build host |
| Build requirements pulled from PyPI at build time | `pyodide-build` installs the project's `build-system.requires` (plus extras) into an isolated venv. It applies no pinning or hash checking of its own | A compromised or yanked-and-replaced build dependency runs on the build host |

Mitigation guidance:

- Build in an ephemeral, unprivileged environment (container or CI runner) with no long-lived secrets.
- Do not expose publish credentials to jobs that build untrusted or pull-request code. Use a separate job for publishing.

### 5.2 Cross-build environment (`xbuildenv`)

`pyodide-build` downloads a cross-build environment archive and unpacks it on the host. The download URL comes from release metadata fetched over HTTPS from a default URL.

- The contents of the xbuildenv (compilers' sysroot, headers, static libraries, host packages) end up inside every package built with it. A tampered xbuildenv can therefore compromise built wheels, not just the build host.
- Inputs that select the archive are trusted by design: the `url` argument of `pyodide xbuildenv install`, the default URL from configuration, and the `PYODIDE_CROSS_BUILD_ENV_METADATA_URL` environment variable. Anyone who can set them controls what runs on the build host.
- The `dev` xbuildenv is published to an S3 bucket (`pyodide-cache`) from CircleCI with static AWS keys and `--overwrite`, so it is mutable by design. Do not use it for reproducible or security-sensitive builds.

### 5.3 CDN distribution

Runtime files and the package set are served from the jsDelivr CDN (`cdn.jsdelivr.net/pyodide/v<version>/full/`).

| Threat | Current state | Residual risk |
| --- | --- | --- |
| Package wheel tampered with on the CDN | `pyodide-lock.json` records a `sha256` per package, and `loadPackage` verifies it through fetch subresource integrity | Integrity is only as strong as the lock file |
| `pyodide-lock.json` or `pyodide.js` tampered with | These come from the same origin as the packages, so the hashes provide no protection against a CDN-level compromise | A compromised CDN path or account replaces everything consistently. Users who need stronger guarantees should self-host or pin their own copy |
| Mutation of released versions | Release files are uploaded by CircleCI to the S3 bucket behind jsDelivr. | Immutability is enforced by the upload script and by cache headers, not by the bucket. Anyone with the S3 credentials can overwrite objects |
| `dev` channel | Uploaded on every main-branch build | Mutable by design. Anyone loading `dev` follows the main branch |
| Upload credentials | The CDN bucket is written with AWS access keys held in CircleCI. The npm package uses OIDC trusted publishing | Long-lived AWS keys. |

Recommendation for users: self-host the runtime and package set from a trusted origin, pin versions, and publish your own SRI hash for `pyodide.js`.

### 5.4 Packages installed at runtime (`micropip`)

- Wheels from PyPI are checked against the `sha256` that the index provides (`wheelinfo.py`). Wheels from arbitrary URLs have no hash unless the caller supplies one.
- Installing a wheel runs no build step, but importing it runs its Python code in the page.
- The default index list is PyPI only.

### 5.5 Release and CI

Risks and open items:

- A compromised maintainer account or a malicious change to a release workflow can publish a malicious release.
- Cache poisoning across jobs.

## 6. Out of scope

- Running untrusted Python in Pyodide when the embedding application shares its origin with sensitive data and adds no isolation.
- Vulnerabilities in the browser, the JavaScript engine or Node.js, including WebAssembly sandbox escapes. Report these to the vendor.
- Side-channel and speculative-execution attacks, including Spectre-class attacks.
- Denial of service through resource exhaustion by code running inside Pyodide, such as memory and CPU consumption.
- Vulnerabilities in third-party packages. Report these upstream. We track them for packages we build.
- Compromise of the user's own machine, browser or network (for example a malicious extension, or TLS interception with a trusted CA).

## 7. What we treat as a vulnerability

Examples of reports we want:

- Code execution on a build host from a recipe or `pyodide-build` input that a reasonable maintainer would consider safe to build.
- Integrity bypass: loading a package, runtime file or xbuildenv whose hash does not match the one that is expected.
- A flaw in the release or CI process that lets an unprivileged party publish or alter a release.
- Pyodide-specific behavior (the JS/Python bridge, package loading) that breaks the assumptions in §3.
- Leakage of secrets from CI logs or artifacts.
