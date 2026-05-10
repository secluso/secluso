# Secluso Release Verification Guide

This README is to explain how Secluso releases are verified and what guarantees that verification is intended to provide.

There are two related but distinct cases. One is the regular Secluso binaries, such as Raspberry Pi and server artifacts. The other is the Secluso deploy tool, which is a desktop application for Linux, macOS, and Windows. Those two cases share the same reproducible-build philosophy, but the desktop operating systems have different release requirements, so the verification model is described carefully below to reflect that.

If you only want to verify a release, use the commands in the next section. If you want the technical details and exact guarantees, please see the below sections.

## Fast Path

For the deploy-tool release, authenticate the release files you downloaded before comparing any build output. From the deploy-tool release-asset directory shown in this guide, verify the maintainer-signed checksum file first, then verify the files named by that checksum file:

    gpg --verify secluso-vX.Y.Z-sha256sums.txt.jkaczman.asc secluso-vX.Y.Z-sha256sums.txt
    gpg --verify secluso-vX.Y.Z-sha256sums.txt.arrdalan.asc secluso-vX.Y.Z-sha256sums.txt
    sha256sum -c secluso-vX.Y.Z-sha256sums.txt

Both checksum signatures should be checked for complete assurance. The signing keys are the same project co-founder keys listed in SECURITY.md: Ardalan Amiri Sani, fingerprint 1A9A1BA3090FA78E946DC0C0301497925DCCE876, and John Kaczman, fingerprint 7785755F1A24FF04CE0E12575DF5E79230C57C4A. This step proves that the files on disk are the files covered by the signed checksum statement. Use the same pattern for regular binary release bundles. The reproducible-build checks below then prove what those files correspond to.

Before rebuilding, make sure your source checkout is the release source revision:

    git fetch --tags
    git tag -v RELEASE_TAG
    git switch --detach RELEASE_TAG

If a release is bound to an exact commit instead of a signed tag, compare git rev-parse HEAD against the commit published with the release. Do not use a moving branch name (such as the main branch) as the source identity for a verification run.

To verify the regular Secluso binaries, rebuild the same target and profile as the release you want to check. For example, if you are verifying a Raspberry Pi release, run:

    ./build.sh --target raspberry --profile all

Then compare your run against the unpacked official verification bundle for that release:

    ./build.sh --compare builds/TIMESTAMP official-binaries

Use the run directory that directly contains manifest.json. Do not point compare at an inner artifacts/ directory. If everything matches, the script prints Reproducibility check PASSED.

To verify the Linux deploy tool, build the matching Linux deploy profile:

    ./build.sh --target deploy --profile linux

Then compare that run against the unpacked official Linux deploy-tool verification bundle:

    ./build.sh --compare builds/TIMESTAMP official-deploy-linux

To verify the macOS deploy tool, first build the matching unsigned local app:

    ./build.sh --target deploy --profile macos-arm64

Then verify the signed release against that local build:

    ./verify_macos_release.sh --local-run builds/TIMESTAMP --triple aarch64-apple-darwin --release /path/to/Secluso-Deploy-1.0.0-macos-arm64.app.zip

The macOS verifier must be run on macOS with codesign, spctl, and xcrun stapler available, usually macOS with the Xcode Command Line Tools installed. 

To verify the Windows deploy tool, first build the matching unsigned local installer:

    ./build.sh --target deploy --profile windows-x64

Then verify the distributed signed release against that local build:

    ./verify_windows_release.sh --local-run builds/TIMESTAMP --triple x86_64-pc-windows-msvc --release /path/to/Secluso-Deploy-1.0.0-windows-x64-setup.exe [--signtool PATH]

The Windows verifier must be run somewhere Microsoft signtool and PowerShell's Get-AuthenticodeSignature are available, usually Windows with the Windows SDK installed or Git Bash pointing at signtool.exe.

## The Main Idea

Secluso supports two different verification paths. The regular Secluso binaries and the Linux deploy-tool artifacts are verified by direct reproducible-build comparison. The macOS and Windows deploy-tool artifacts are verified as signed (platform-based) releases. In the first path, the released file itself is expected to be byte-for-byte identical to a local rebuild. In the signed macOS and Windows paths, the released file is expected to differ from the unsigned local build **ONLY** where Apple or Microsoft signing requires it to differ, and the verifier then checks that every remaining byte still matches the reproducible local build.

Linux allows for distributing the deploy tool as a directly reproducible artifact. macOS and Windows cannot be distributed in a platform-accepted form without additional signing state. A public macOS release needs Developer ID signing, hardened runtime, notarization, and a stapled ticket. A public Windows release needs Authenticode signing and a trusted timestamp. Those platform signing steps modify the artifact after the unsigned reproducible build is produced, so the verifier has to perform a much more precise verification than a raw file hash comparison.

The chain of trust here has three parts. The signed checksum file authenticates the downloaded release files as the maintainer-published files. The authenticated release source revision and local rebuild establish the payload that should be produced from the pinned build inputs. The platform-specific verifiers then prove that the macOS and Windows signing bytes are confined to OS-defined signing metadata, while every executable or installer-payload byte outside those regions matches the local reproducible build.

## What The Verification Guarantees Mean

For the regular Secluso binaries and for the Linux deploy-tool artifacts, the guarantee is simple. If verification passes, the released artifact matches a local rebuild byte-for-byte. The compare logic checks metadata first so that you are not comparing unlike inputs, then it recomputes hashes from disk and requires the actual produced files to match exactly. If the inputs differ, the compare step explains that mismatch. If the inputs match but the resulting artifact bytes do not, verification fails.

For macOS and Windows deploy-tool releases, the guarantee has a different scope. It is not a raw-file guarantee, because the platform-accepted release artifact is expected to contain signing material that the unsigned local build does not contain. The verifier instead checks the following two properties, that the distributed release satisfies the platform's signing policy, and every byte outside the exact signing-managed regions still matches the unsigned reproducible build. That is a byte-for-byte **payload** guarantee for signed desktop releases.

## How Direct Comparison Works

The direct comparison path is the one used for the regular Secluso binaries and for Linux deploy-tool artifacts. build.sh writes a run directory containing a manifest.json, the produced artifacts, and a distributable verification bundle. The official comparison input must be that verification bundle or an equivalent run-style directory containing manifest.json and the artifact paths named by it, not just a folder of user-facing binaries. In compare mode, the script does not simply trust the hashes recorded in the manifest. It recomputes the hashes from disk and checks that the files actually match what the manifest claims. It also checks that the compared runs agree on the relevant build identity information, such as crate version, lock digest, and toolchain identity, before treating the byte comparison as meaningful.

Reproducibility is only useful when you compare like with like. If metadata already differs, then a byte mismatch is not very informative. If the metadata matches and the bytes still differ, that is the situation that should be taken as an actual reproducibility failure.

## The macOS Technical Guarantee

verify_macos_release.sh compares the signed, notarized, and stapled public app against the unsigned reproducible local app. It first checks the release-policy side via codesign verification, matching bundle identifier, expected Team ID, hardened runtime, stapled notarization ticket, xcrun stapler validation, and spctl assessment. Those checks show that the artifact is accepted by the verifier host's Apple tooling under the expected release policy and signing identity. They are NOT treated as proof that the app is benign or source-reproducible.

After that policy check, the script performs the reproducibility side of the verification. It materializes a copy of the distributed app, normalizes the release-signing and distribution metadata Apple packaging is allowed to introduce, and then compares that normalized result against the local build. That includes checking the entitlements policy, checking stable Mach-O CodeDirectory page hashes against the local build, and checking the layout invariants around signature regions. The technical guarantee is, therefore, if the script passes, the app is both a valid Apple release artifact and still the same app you would have built locally, modulo the exact Apple-managed signing and distribution metadata regions that must differ.

The Mach-O part of this check depends on how macOS records code-signing data. LC_CODE_SIGNATURE points to a bounded signing envelope, and the CodeDirectory describes signed code pages through fields such as hash offset, number of code slots, code limit, hash size, hash type, page size, team offset, runtime flags, and the CodeDirectory hash table. The verifier uses that structure to distinguish Apple signing metadata from executable payload and to refuse a release whose stable code pages no longer match the reproducible local build.

For the current macOS arm64 release artifact, the split looks like this:

```text
Mach-O executable: 30,950,368 bytes

  [ compared payload ........................................ ] [ Apple signing envelope ]
    30,871,600 bytes                                            78,768 bytes
    99.746%                                                     0.254%

LC_CODE_SIGNATURE envelope:

  [ CodeDirectory ......................... ] [ CMS/ticket ] [ tail ]
    60,542 bytes                              9,161 bytes    9,029 bytes

CodeDirectory:

  slots in signed hash table : 1,885 x 16,384-byte pages
  stable slots recomputed    : 1..1,884
  first-page slot            : covered by normalized Mach-O compare because Apple mutates header/load-command signing state
  hash table size            : 60,320 bytes

Verifier treatment:

  normalized app payload        -> compared byte-for-byte against local build
  CodeDirectory page hashes     -> stable post-header slots are recomputed from local build pages, so the signed hash table must describe the same executable code
  signature tail                -> must match local signature-region tail bytes at the same offsets. It is not accepted as free-form data
  CMS/notary ticket             -> accepted only as Apple signing/notarization evidence after codesign, stapler, and spctl policy checks
```

macOS sources for the signing model and policy:

- [LLVM CS_CodeDirectory](https://llvm.org/doxygen/structllvm_1_1MachO_1_1CS__CodeDirectory.html)
- [Go codesign.go](https://go.dev/src/cmd/internal/codesign/codesign.go)
- [XNU cs_blobs.h](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [LIEF Mach-O Modification](https://lief.re/doc/stable/tutorials/11_macho_modification.html)
- [Notarization: is a notarized app safe to use?](https://eclecticlight.co/2021/01/05/notarization-is-a-notarized-app-safe-to-use/)
- [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [Apple Accidentally Approved Malware to Run on MacOS](https://www.wired.com/story/apple-approved-malware-macos-notarization-shlayer/)

## The Windows Technical Guarantee

verify_windows_release.sh compares the Authenticode-signed public installer against the unsigned reproducible local installer. It first checks the release-policy side via signtool verification, a primary signature, a trusted timestamp, the expected publisher identity, and the pinned signer certificate SHA-1 thumbprint for this release. Those checks show that the artifact is accepted by the verifier host's Windows tooling under the expected signing policy and publisher identity. They are not a reproducibility proof on their own.

Authenticode signing changes the byte comparison because the signature is not computed over the file as one uninterrupted byte stream. Microsoft's PE signing explainer says the signing provider "does not hash all of the bytes of the file" and specifies the PE checksum and certificate-table directory as omitted fields. The verifier accounts for those rules by zeroing the fixed PE bookkeeping fields in both views before comparing. The certificate table is handled differently. It is not accepted as arbitrary ignorable slack.. the verifier checks that it is the PE security directory, that it is bounded by the file format, that it is at EOF for this release artifact, and that removing it leaves an installer payload that matches the unsigned reproducible build.

The certificate directory is a file-offset certificate table, not a normal RVA-mapped executable section. The Windows loader does not load that certificate table into the program address space as ordinary code or data. That does not make the certificate table safe in a broad sense, it only explains why the verifier can treat it as a bounded signing envelope after checking PE placement, EOF bounds, and alignment.

After normalization, the rest of the file must match the unsigned local reproducible build **exactly**. The technical guarantee is, therefore, if the script passes, the installer is both a valid signed Windows release and still the same installer payload you would have built locally, except for the exact Authenticode-controlled regions that necessarily differ.

For the current Windows x64 release artifact, the relevant split looks like this:

```text
Signed installer: 13,757,760 bytes

  [ compared payload ........................................ ] [ Authenticode ]
    13,742,115 bytes                                            15,645 bytes
    99.886%                                                     0.114%

Normalized-away Authenticode bytes:

  checksum field              4 bytes   -> zeroed in both views
  security directory          8 bytes   -> zeroed in both views
  certificate alignment pad   5 bytes   -> removed only if trailing NUL pad
  WIN_CERTIFICATE        15,640 bytes   -> must be final EOF structure

Verifier treatment:

  normalized installer payload     -> compared byte-for-byte against local build
  WIN_CERTIFICATE                  -> parser verifies PE placement, EOF bounds, and alignment. signtool verifies Authenticode chain, publisher, and timestamp. the script pins the expected signer certificate thumbprint
  certificate alignment pad        -> removed only if it is trailing NUL padding and at most the 7 bytes needed for 8-byte alignment
  checksum + security directory    -> fixed-size PE bookkeeping fields; zeroed in both views, not accepted as executable payload
```

Windows sources for Authenticode and PE signing behavior:

- [Understanding executable file signing](https://learn.microsoft.com/en-us/windows/win32/secbp/understanding-pe-signatures)
- [PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Verifying Windows binaries, without Windows](https://blog.trailofbits.com/2020/05/27/verifying-windows-binaries-without-windows/)
- [LIEF PE Authenticode](https://lief.re/doc/latest/tutorials/13_pe_authenticode.html)
- [osslsigncode pe.c](https://sources.debian.org/src/osslsigncode/2.9-2/pe.c/)

## Limits Of What This Proves

If verification passes, that is strong evidence that the released distributed artifact matches what should come out of that source revision and those pinned build inputs. It does not prove that the source code itself is safe, and it does not make a single untrusted run directory authoritative on its own. The check should be run when at least one side of the comparison comes from somewhere independent, such as a separate build machine you control.

The signed macOS and Windows metadata should not be described as "safe" in a broad sense. The concrete guarantee is that those bytes are bounded by platform file-format parsers, accepted by platform signing tools, and removed or normalized before every remaining executable or installer-payload byte is compared against the local reproducible build. They are not accepted as normal OS-loaded app or installer payload under this verifier model. This does not separately prove that arbitrary application code could never read its own signature metadata as data.
