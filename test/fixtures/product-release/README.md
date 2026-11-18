# Product release conformance corpus

This directory is the native consumer copy of the canonical product contracts from `/Users/vitaly/voboost/voboost/release` on 2026-10-22.

The native parser tests consume the same accepted and rejected `voboost.json` and `restore.json` fixtures. `status/` adds the channel-independent app/daemon proposal, active-identity, result and descriptor-handoff wire examples owned by `voboost-inject`, including transaction/manifest alias and descriptor alias rejection.

Canonical source hashes at import:

```text
voboost.schema.json  293a2ccf7cdeb193e3ae31d695eebbd8146f8ec1269abe6feae043e85bbecdaf
restore.schema.json  519d16dafc5462a6ea457535bd8a4966e26fb9b7e72831c49e88cd46281cb0bb
voboost/valid/minimal.json  a5d3d1a2be693a90c554522301acdec289c78a04efb335d4a1293ab849677f3f
voboost/valid/version-code-max.json  b2a99d23c483a72a820bf00318e6147efc44075705ffa7a5b7cc8082f13b1eaf
voboost/invalid/version-code-zero.json  dac56ff33937230e1c56aefca6d8d357a91aecb7ec942505081d8981b3ac607e
voboost/invalid/version-code-over-max.json  6ad855607ba85371470ff8b2c2746bf8e1c9c9bc5dee7500fac8356236cb88a3
status/proposal-transaction-equals-manifest.json  493f0a66bafa722e96af21081b5b80123a9e60abf8e26767b7892e7cf76274f6
status/descriptors.json  408ef27e20fb8ad5a4e314ba0d62c79a5219044d8cb5d1c12b24e8b6b7e270a5
status/descriptors-aliased.json  de2184c6ebdfdca812939dcb14a7eec06012756d493f9b88ca3d1dab197a08d0
bounds.json  5cfcf1f9eca32e5dcb4f21a2225cc52d4db063d3b7b8022e4d7bd6ee9996e82d
status/proposal-metadata-only.json  811424f4605a46be369bf87eaa85126ad77543015c3362ab7978aa8df6e9bbb7
status/proposal-stale-release.json  9e109f50f1fb1518150570c05dc48052aebe5720251513f98f8bee35d7956c36
status/descriptors-metadata-only.json  3a870cd95d1f2e85a66e34573e5a69bf72e9350a9f28a4fe25c847605b4abae5
status/descriptors-missing-manifest.json  b7b95a14bda71f9a6531ba372b34aca765449dbe619648cbbcce1111f648a59c
status/descriptors-missing-signature.json  cea10fb3110020d2b733652a4a2f911f28f908d1fe0064a12f127cc9aae169c9
status/active-strictly-older-beta.json  310fab74e796abe0321637e45a1a08a122bf9a313a9ac480474352f4b27aa630
status/active.json  d056ec53fd0635e72517862a271c0916b92b51c054754c89fcd3552119ce2670
status/active-newer-beta.json  4453fec6b69059d54893ed890be11c46e790aeb3c4b7d37fecb7217b3b1a5f29
status/active-cross-channel-stable.json  c3b7af6c676fd9d1c8f5e5c627a738a463ab41ecdd5e2fefd0b6a8999d4697bc
status/active-malformed.json  fb22dbf8d0186a82acbf5975d4e1f6af9cc657e952cfb7f7861b38ead109e517
```

Do not add `channel.json` here. The privileged device contract begins with exact signed `voboost.json` bytes and contains no URL or channel-selection authority.
