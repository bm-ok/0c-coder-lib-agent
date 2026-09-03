# trustcrypto/onlykey-agent#42 in lib-agent: confirmed, reproduced, fixed

Branch: `check/agent-uid-42`. Only this repository was touched.

The previous round established the defect by reading the code. This round
reproduces it with a test that runs without a device, an emulator or `gpg`,
then fixes it. Everything below was actually executed on this machine
(Ubuntu, Linux 6.8, CPython 3.12.3).

---

## 1. Is `lib-agent` what the OnlyKey project setup actually uses for GPG?

**Yes.** The GPG agent binaries the project ships are thin wrappers whose entire
implementation is this repository.

* `agents/onlykey/setup.py` builds the PyPI package **`onlykey-agent`** (version
  1.1.16). It declares `install_requires=['lib-agent>=1.0.6', 'onlykey>=1.2.8']`
  and these `console_scripts`:

  | script | entry point |
  | --- | --- |
  | `onlykey-agent` | `onlykey_agent:ssh_agent` |
  | `onlykey-gpg` | `onlykey_agent:gpg_tool` |
  | `onlykey-gpg-agent` | `onlykey_agent:gpg_agent` |

* `agents/onlykey/onlykey_agent.py` is 12 lines: `gpg_agent = lambda:
  gpg.run_agent(DeviceType)` with `from libagent import ... gpg ...` and
  `from libagent.device.onlykey import OnlyKey as DeviceType`. So
  `onlykey-gpg-agent` **is** `libagent.gpg` — including `libagent/gpg/agent.py`,
  the file this issue is about.

* The repository's own `setup.py` (package `lib-agent`, version 1.0.8) installs
  the `libagent.*` packages and declares **no** console scripts. The scripts come
  only from `agents/onlykey/setup.py`.

Cross-repository, in this workspace:

* `node-onlykey-emulator/setup.sh:253` provisions the venv every test run uses:

  ```sh
  "$VENV/bin/pip" install -e "$CHECKOUTS/lib-agent" -e "$CHECKOUTS/lib-agent/agents/onlykey"
  ```

  with the comment at `setup.sh:250-251` naming the result:
  `lib-agent -> the agent framework` / `onlykey-agent -> onlykey-agent, onlykey-gpg`.
  `setup.sh:182` pins the checkout to `https://github.com/bm-ok/0c-coder-lib-agent`
  — this repository.
* `onlykey-testing/lib/cli.js` resolves its tools out of that same venv
  (`okpqc-venv/bin`, see `cli.js:5`), and `onlykey-testing/test/02-cli/09-lib-agent-gpg.test.js`
  drives `onlykey-gpg init` against it.

So the checkout in this workspace is the code that installs as
`onlykey-gpg-agent`, and it is the GPG agent the test kit exercises. No other
repository here vendors or forks a second copy of `libagent`.

**Negative part of the answer:** nothing in this workspace pins a *released*
`lib-agent` version from PyPI — the only installs are editable installs of this
checkout — so there is no second, older copy in play.

---

## 2. Commands run

From `/home/okc/workspace/lib-agent`:

```sh
# tooling venv, inside this checkout only ('env/' is already in .gitignore)
python3 -m venv env
./env/bin/pip install --upgrade pip tox

# full gate exactly as CI runs it (.github/workflows/ci.yml -> `tox`)
./env/bin/tox

# individual steps, using the environment tox built at .tox/py3
.tox/py3/bin/pycodestyle libagent
.tox/py3/bin/isort --skip-glob .tox -c libagent
.tox/py3/bin/pylint --reports=no --rcfile .pylintrc libagent
.tox/py3/bin/pydocstyle libagent
.tox/py3/bin/python -m pytest -v libagent
```

To reproduce the "fails before, passes after" claim without editing anything:

```sh
git checkout 0478271                       # tests only, fix not yet applied
.tox/py3/bin/python -m pytest -v libagent/gpg/tests/test_agent.py   # 2 failed
git checkout check/agent-uid-42
.tox/py3/bin/python -m pytest -v libagent/gpg/tests/test_agent.py   # 3 passed
```

Nothing was installed system-wide, and no other repository was modified.

---

## 3. Results

### 3a. Baseline, before any change

`pytest`: **81 passed, 0 failed, 0 skipped** (2.42s).

`tox` **already fails at baseline**, at its first command, on a file unrelated to
this issue. Recorded here so it is not mistaken for damage from this change —
all of it is in `libagent/device/onlykey_pqc.py`:

```
py3: commands[0]> pycodestyle libagent
libagent/device/onlykey_pqc.py:37:13: E221 multiple spaces before operator
libagent/device/onlykey_pqc.py:38:7: E221 multiple spaces before operator
libagent/device/onlykey_pqc.py:40:14: E221 multiple spaces before operator
libagent/device/onlykey_pqc.py:122:11: E221 multiple spaces before operator
py3: exit 1 (0.64 seconds)
```

Running the remaining gates individually at baseline:

* `isort` — clean (rc=0).
* `pylint` — rc=14, 6 messages, **all** in `libagent/device/onlykey_pqc.py`
  (W0718, E0401, W0613 ×2, R0913, W0611). Rated 9.97/10.
* `pydocstyle` — rc=1, 3 messages (D205/D209/D400), all in
  `libagent/device/onlykey_pqc.py:75`.

These pre-existing failures were **not** fixed — that is not what was asked, and
touching that file would be unreviewed work in this change.

### 3b. The new tests, on the UNFIXED code

`.tox/py3/bin/python -m pytest -v libagent/gpg/tests/test_agent.py` at commit
`0478271` (tests added, `agent.py` untouched). Pasted verbatim except where
marked `...`, where the repeated body of `get_identity` is elided:

```
============================= test session starts ==============================
platform linux -- Python 3.12.3, pytest-9.1.1, pluggy-1.6.0
collected 3 items

libagent/gpg/tests/test_agent.py::test_sig_encode PASSED                 [ 33%]
libagent/gpg/tests/test_agent.py::test_get_identity_uses_user_id_matching_keygrip FAILED [ 66%]
libagent/gpg/tests/test_agent.py::test_get_identity_without_matching_user_id FAILED [100%]

=================================== FAILURES ===================================
_______________ test_get_identity_uses_user_id_matching_keygrip ________________

    def test_get_identity_uses_user_id_matching_keygrip(monkeypatch):
        # The key belongs to the SECOND user ID of a two-user-ID public key.
        keygrip, pubkey_bytes = _public_key_blob(
            derived_from=USER_ID_SECOND,
            user_ids=[USER_ID_FIRST, USER_ID_SECOND])
        handler = _handler(monkeypatch, pubkey_bytes)
>       identity = handler.get_identity(keygrip=keygrip)

libagent/gpg/tests/test_agent.py:83:
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _
libagent/util.py:230: in wrapper
    result = method(self, *args, **kwargs)
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

self = <libagent.gpg.agent.Handler object at 0x7cdcde827d10>
keygrip = b'992EDD7680225972C610CF7C6C9B0279A46E4319'

    @util.memoize_method  # global cache for key grips
    def get_identity(self, keygrip):
        keygrip_bytes = binascii.unhexlify(keygrip)
        pubkey_dict, user_ids = decode.load_by_keygrip(
            pubkey_bytes=self.pubkey_bytes, keygrip=keygrip_bytes)
        # We assume the first user ID is used to generate Agent-based GPG keys.
        user_id = user_ids[0]['value'].decode('utf-8')
        if pubkey_dict['algo'] not in {1, 2, 3}:
            ...
>           assert pubkey.key_id() == pubkey_dict['key_id']
E           AssertionError

libagent/gpg/agent.py:206: AssertionError
__________________ test_get_identity_without_matching_user_id __________________

    def test_get_identity_without_matching_user_id(monkeypatch):
        ...
        with pytest.raises(KeyError):
>           handler.get_identity(keygrip=keygrip)

libagent/gpg/tests/test_agent.py:96:
...
>           assert pubkey.key_id() == pubkey_dict['key_id']
E           AssertionError

libagent/gpg/agent.py:206: AssertionError
=========================== short test summary info ============================
FAILED libagent/gpg/tests/test_agent.py::test_get_identity_uses_user_id_matching_keygrip
FAILED libagent/gpg/tests/test_agent.py::test_get_identity_without_matching_user_id
========================= 2 failed, 1 passed in 0.18s ==========================
```

That is the defect, reproduced: a bare `AssertionError` at `agent.py:206`, which
is exactly what escapes `Handler.handle()` (it catches only `AgentError`) and
reaches the user as `gpg: signing failed: End of file`. The second failure shows
the same for the "no user ID matches" case, where GnuPG should get a *diagnosable*
missing-key answer instead.

### 3c. The same tests, after the fix

```
libagent/gpg/tests/test_agent.py::test_sig_encode PASSED                 [ 33%]
libagent/gpg/tests/test_agent.py::test_get_identity_uses_user_id_matching_keygrip PASSED [ 66%]
libagent/gpg/tests/test_agent.py::test_get_identity_without_matching_user_id PASSED [100%]

============================== 3 passed in 0.13s ===============================
```

### 3d. Full suite, after the fix

```
.tox/py3/bin/python -m pytest -q libagent
........................................................................ [ 86%]
...........                                                              [100%]
83 passed in 1.65s
```

81 at baseline + 2 new = 83. Nothing that passed before fails now.

Lint after the fix, filtered to show that the only remaining messages are the
pre-existing `onlykey_pqc.py` ones from 3a:

* `pycodestyle` — no new messages; only the four baseline `onlykey_pqc.py` E221s.
* `isort` — clean (rc=0).
* `pylint` — still 9.97/10; no messages in any file this change touched.
  (Two new messages appeared in a first draft of the test file, R0903 and W0613;
  both were removed rather than left to accumulate.)
* `pydocstyle` — no new messages; only the three baseline `onlykey_pqc.py` ones.

`tox` as a whole still exits non-zero, for the baseline reason and no other.

---

## 4. What changed, file by file

### `libagent/gpg/agent.py`

`Handler.get_identity` used to take `user_ids[0]` and derive from it, asserting
afterwards that the result matched. Now it iterates over the candidates and keeps
the first that reproduces the key GnuPG asked about:

* Split the per-user-ID derivation out into a new private method
  `Handler._derive_identity(user_id, keygrip, keygrip_bytes, pubkey_dict)`. It
  returns the `Identity` if the derived key matches, and `None` if it does not.
  The correctness rule is the one the old `assert` already encoded — `key_id()`
  **and** `keygrip()` must both match — it is now a decision instead of a crash.
* `get_identity` loops over **all** the user ID packets `decode.load_by_keygrip`
  already returns, and returns the first match.
* When no candidate matches, it raises
  `KeyError('<keygrip> keygrip does not match any user ID')`. `KeyError` is
  deliberate: it is what the method's own docstring already promises, what
  `decode.load_by_keygrip` already raises for a missing keygrip, and what
  `Handler.have_key`'s `except KeyError` already catches — so key probing now
  turns into GnuPG's proper `ERR 67108881 No secret key` instead of an
  `AssertionError` escaping the handler.
* **RSA-2048/4096 branches: given the same verification.** They previously had no
  check at all. `protocol.PublicKey.key_id()` cannot be used for RSA (its
  `data()` returns `header + util.bytes2num(...)`, i.e. bytes + int, which raises
  `TypeError` — the RSA `PublicKey` objects were constructed but never used), so
  instead the modulus the device returns is fed through
  `protocol.keygrip_rsa(modulus, modulus.bit_length())` and compared to the
  requested keygrip. That is byte-for-byte the same computation
  `decode._parse_pubkey` (`decode.py:181`) used to derive the keygrip in the
  first place. The now-unused `pubkey = protocol.PublicKey(...)` construction in
  those two branches was dropped with them (leaving it would be a `pylint`
  unused-variable once the branches are in their own method).
* The `else` fall-through for an unrecognised key size used to set
  `identity = 'unknown identity type'` and **return the string**, so callers hit
  `AttributeError: 'str' object has no attribute 'curve_name'`. It now logs the
  same message and yields no candidate, so the function ends in the `KeyError`
  its docstring promises.
* Deleted the comment `# We assume the first user ID is used to generate
  Agent-based GPG keys.` and replaced it with one stating why the keygrip cannot
  be used to pick the user ID.

Cost: the loop is inside the `@util.memoize_method`-decorated `get_identity`, so
it is at most one extra device round-trip per *unmatched* user ID, once per
keygrip per agent run. No new unmemoized loop was introduced, and the common
single-user-ID case does exactly one round-trip, as before.

### `libagent/gpg/decode.py`

One line: the `load_by_keygrip` docstring said *"Return public key and first user
ID for specified keygrip."* It has always returned **all** of them (`user_ids =
[p for p in packets if p['type'] == 'user_id']`); the caller was the thing
throwing them away. Corrected to "all user IDs". No behaviour change and no
interface change.

### `libagent/gpg/tests/test_agent.py`

Two new tests plus their helpers. They build an OpenPGP public key **in memory** —
one public-key packet followed by two user-ID packets, via `protocol.packet` —
whose key material is derived from a chosen user ID. A `FakeDevice` stands in for
the hardware and derives a distinct NIST256 key per identity by hashing
`Identity.to_bytes()`, the same input `libagent/device/onlykey.py:197-200` hashes
(and, like it, one that does **not** include the keygrip). `keyring.gpg_version`
is monkeypatched so no `gpg` binary is needed.

* `test_get_identity_uses_user_id_matching_keygrip` — key belongs to the *second*
  of two user IDs; asks for its keygrip; asserts the returned identity's host is
  the second user ID, and that the device was asked about both user IDs in order
  (i.e. the match was found by verifying, not by luck).
* `test_get_identity_without_matching_user_id` — key belongs to neither user ID;
  asserts `KeyError`, the failure mode `have_key` and GnuPG can act on.

Both are pinned to `get_identity` itself, the method on the `PKSIGN`, `PKDECRYPT`
and `HAVEKEY` paths. No hardware, no emulator, no `gpg`.

---

## 5. What I could not verify, and the one thing I could

### Verified: stored slots vs derived slots (the blast radius)

The brief flagged this as probably unverifiable. It is verifiable from the
firmware checkout that is in this workspace, so here it is — this bounds *who*
is affected, and does not change whether the defect exists:

`libraries/onlykey/okcrypto.cpp:269-292`, `okcrypto_getpubkey()`, dispatches on
the slot id in `buffer[5]`:

* `buffer[5] < 5` → `okcore_flashget_RSA()`; `buffer[5] < 117` →
  `okcore_flashget_ECC()`. Both return a **stored** key. The 32-byte payload
  lib-agent computed from the identity is **not read** on these paths.
* `buffer[5] == RESERVED_KEY_DERIVATION` (= **132**, `libraries/onlykey/okcore.h:212`)
  → `okcrypto_derive_key(buffer[6], buffer+7, NULL)`, which at
  `okcrypto.cpp:589-598` does `sha256(default_key || data)` — `data` being exactly
  lib-agent's `sha256(Identity.to_bytes())`.

So:

* **Derived keys (slot 132, the default — `onlykey.py:98 DEFAULT_SLOT = 132`):**
  the user ID string *is* the private key. Picking the wrong user ID derives a
  different key. **This is where the bug bites.**
* **Stored key slots (`--skey-slot=ECCnn`/`RSAn` in `run-agent.sh`, resolved by
  `onlykey.py:77-96 get_key_by_keygrip` / `121-149 get_sk_dk`):** the same key
  comes back whatever the user ID, so the old code's `assert` held and users of
  stored slots were never affected. With this fix they are still not: the very
  first candidate matches, so it is still one round-trip.

### Not verified

* **No end-to-end run against real hardware or the emulator.** The tests here are
  unit-level against `get_identity` with a stubbed device; there is no OnlyKey and
  no gadget on this machine. What is *not* proven by them is that GnuPG's
  end-to-end `PKSIGN` on a real two-user-ID key now succeeds — only that the
  agent selects the correct user ID and that a genuine miss is reported as a
  missing key. To close that, run `onlykey-testing`'s
  `test/02-cli/09-lib-agent-gpg.test.js` against a device or the emulator, with a
  key that has a second user ID added by `gpg --edit-key ... adduid`.
* **The RSA verification path is not exercised by a test.** The new tests cover
  the ECC branch only. The RSA check is written against the shape the device
  actually returns for GPG (`onlykey.py:278-291` returns the raw modulus as
  `bytes`), and it mirrors `decode.py:181`'s own keygrip computation, but I have
  not run an RSA key through it. A device or a recorded RSA transcript would be
  needed. If a device were ever to return something other than bytes there,
  `util.bytes2num` would raise rather than silently accept a wrong key — a loud
  failure, but not the `KeyError` the ECC path gives.
* **User attribute packets (tag 17)** are parsed by `decode.py` as
  `'user_attribute'`, not `'user_id'`, so they are not candidates. That matches
  the previous behaviour and I did not change it; if a key's derivation input
  were ever a user attribute, it would still not be found.
* **`tox` still exits non-zero**, for the pre-existing `onlykey_pqc.py` lint
  failures described in 3a. I did not fix them; a green `tox` needs that file
  cleaned up, which is a separate change.

---

## Commits on this branch

* `0478271` — the two failing tests, with `agent.py` untouched, so the "fails
  without the fix" claim is checkable by checking out one commit.
* the following commit — the fix in `agent.py`, the `decode.py` docstring
  correction, and this report.
