extern crate std;

use soroban_sdk::{
    auth::Context, contract, contractimpl, testutils::Events, vec, Address, Bytes, Env, Event,
    IntoVal, Map, String, TryFromVal, Val, Vec,
};

use crate::{
    policies::{
        spending_limit::{self, SpendingLimitAccountParams},
        Policy,
    },
    smart_account::{
        storage::{
            add_context_rule, add_signer, get_context_rule, reconcile_signers,
            reconcile_signers_no_events, validate_signers_and_policies, ContextRule,
            ContextRuleType, PolicyEntry, Signer, SignerEntry, SmartAccountStorageKey,
        },
        SignerAdded, SignerDeregistered, SignerRegistered, SignerRemoved, MAX_SIGNERS,
    },
};

/// Exposes `reconcile_signers` as an entry point so that failing calls can be
/// observed through `try_` without unwinding the test.
#[contract]
struct MockAccount;

#[contractimpl]
impl MockAccount {
    pub fn reconcile(e: &Env, id: u32, signers: Vec<Signer>) -> Vec<u32> {
        reconcile_signers(e, id, &signers)
    }

    pub fn add(e: &Env, id: u32, signer: Signer) -> u32 {
        add_signer(e, id, &signer)
    }

    pub fn validate(e: &Env, signer_count: u32, policy_count: u32) {
        let signer_ids = Vec::from_iter(e, 0..signer_count);
        let policy_ids = Vec::from_iter(e, 0..policy_count);
        validate_signers_and_policies(e, &signer_ids, &policy_ids);
    }
}

#[contract]
struct MockPolicyContract;

#[contractimpl]
impl Policy for MockPolicyContract {
    type AccountParams = Val;

    fn enforce(
        _e: &Env,
        _context: Context,
        _authenticated_signers: Vec<Signer>,
        _rule: ContextRule,
        _smart_account: Address,
    ) {
    }

    fn install(_e: &Env, _param: Val, _rule: ContextRule, _smart_account: Address) {}

    fn uninstall(_e: &Env, _rule: ContextRule, _smart_account: Address) {}
}

#[contract]
struct SpendingLimitPolicy;

#[contractimpl]
impl Policy for SpendingLimitPolicy {
    type AccountParams = SpendingLimitAccountParams;

    fn enforce(
        e: &Env,
        context: Context,
        authenticated_signers: Vec<Signer>,
        rule: ContextRule,
        smart_account: Address,
    ) {
        spending_limit::enforce(e, &context, &authenticated_signers, &rule, &smart_account);
    }

    fn install(
        e: &Env,
        params: SpendingLimitAccountParams,
        rule: ContextRule,
        smart_account: Address,
    ) {
        spending_limit::install(e, &params, &rule, &smart_account);
    }

    fn uninstall(e: &Env, rule: ContextRule, smart_account: Address) {
        spending_limit::uninstall(e, &rule, &smart_account);
    }
}

/// Treats the first 65 bytes of the key as its identity, like the WebAuthn
/// verifier does with the trailing credential id.
#[contract]
struct MockVerifierContract;

#[contractimpl]
impl MockVerifierContract {
    pub fn verify(_e: &Env, _hash: Bytes, _key_data: Val, _sig_data: Val) -> bool {
        true
    }

    pub fn canonicalize_key(e: &Env, key_data: Val) -> Bytes {
        Bytes::try_from_val(e, &key_data).unwrap().slice(0..65)
    }

    pub fn batch_canonicalize_key(e: &Env, key_data: Vec<Val>) -> Vec<Bytes> {
        Vec::from_iter(
            e,
            key_data.iter().map(|key| Bytes::try_from_val(e, &key).unwrap().slice(0..65)),
        )
    }
}

struct Setup {
    e: Env,
    account: Address,
    verifier: Address,
}

impl Setup {
    fn new() -> Self {
        let e = Env::default();
        e.mock_all_auths();
        let account = e.register(MockAccount, ());
        let verifier = e.register(MockVerifierContract, ());
        Setup { e, account, verifier }
    }

    /// A passkey-shaped signer: 65-byte key identity plus a 16-byte
    /// credential id.
    fn passkey(&self, seed: u8) -> Signer {
        self.passkey_with_credential(seed, 0)
    }

    fn passkey_with_credential(&self, seed: u8, credential: u8) -> Signer {
        let mut key = [seed; 81];
        key[65..].fill(credential);
        Signer::External(self.verifier.clone(), Bytes::from_array(&self.e, &key))
    }

    fn passkeys(&self, seeds: core::ops::Range<u8>) -> Vec<Signer> {
        Vec::from_iter(&self.e, seeds.map(|s| self.passkey(s)))
    }

    fn add_rule(&self, signers: &Vec<Signer>, policies: &Map<Address, Val>) -> ContextRule {
        self.e.as_contract(&self.account, || {
            add_context_rule(
                &self.e,
                &ContextRuleType::CallContract(self.verifier.clone()),
                &String::from_str(&self.e, "rule"),
                None,
                signers,
                policies,
            )
        })
    }

    fn reconcile(&self, id: u32, signers: &Vec<Signer>) -> Vec<u32> {
        self.e.as_contract(&self.account, || reconcile_signers(&self.e, id, signers))
    }

    fn rule(&self, id: u32) -> ContextRule {
        self.e.as_contract(&self.account, || get_context_rule(&self.e, id))
    }

    fn signer_entry(&self, signer_id: u32) -> Option<SignerEntry> {
        self.e.as_contract(&self.account, || {
            self.e.storage().persistent().get(&SmartAccountStorageKey::SignerData(signer_id))
        })
    }

    /// Every ledger entry, without TTLs (reads extend TTLs by design).
    fn ledger(&self) -> std::string::String {
        let entries = self.e.to_ledger_snapshot().ledger_entries;
        std::format!(
            "{:?}",
            entries.iter().map(|(key, (entry, _))| (key, entry)).collect::<std::vec::Vec<_>>()
        )
    }

    fn event_count(&self) -> u32 {
        self.e.events().all().events().len() as u32
    }
}

#[test]
fn identical_set_is_a_no_op() {
    let s = Setup::new();
    let signers = s.passkeys(1..4);
    let rule = s.add_rule(&signers, &Map::new(&s.e));
    let before = s.ledger();

    let ids = s.reconcile(rule.id, &signers);

    assert_eq!(ids, rule.signer_ids);
    assert_eq!(s.event_count(), 0);
    assert_eq!(s.ledger(), before);
}

#[test]
fn single_add_keeps_existing_ids() {
    let s = Setup::new();
    let rule = s.add_rule(&s.passkeys(1..3), &Map::new(&s.e));

    let new = s.passkey(3);
    let ids = s.reconcile(rule.id, &s.passkeys(1..4));

    assert_eq!(ids, vec![&s.e, 0, 1, 2]);
    let events = s.e.events().all();
    assert_eq!(events.events().len(), 2);
    assert_eq!(
        events.events().first().unwrap(),
        &SignerRegistered { signer_id: 2, signer: new }.to_xdr(&s.e, &s.account),
    );
    assert_eq!(
        events.events().get(1).unwrap(),
        &SignerAdded { context_rule_id: rule.id, signer_id: 2 }.to_xdr(&s.e, &s.account),
    );

    let after = s.rule(rule.id);
    assert_eq!(after.signers, s.passkeys(1..4));
    assert_eq!(after.signer_ids, ids);
}

#[test]
fn single_remove_releases_only_that_signer() {
    let s = Setup::new();
    let rule = s.add_rule(&s.passkeys(1..4), &Map::new(&s.e));

    let ids = s.reconcile(rule.id, &vec![&s.e, s.passkey(1), s.passkey(3)]);

    assert_eq!(ids, vec![&s.e, 0, 2]);
    let events = s.e.events().all();
    assert_eq!(events.events().len(), 2);
    assert_eq!(
        events.events().first().unwrap(),
        &SignerDeregistered { signer_id: 1 }.to_xdr(&s.e, &s.account),
    );
    assert_eq!(
        events.events().get(1).unwrap(),
        &SignerRemoved { context_rule_id: rule.id, signer_id: 1 }.to_xdr(&s.e, &s.account),
    );
    assert_eq!(s.signer_entry(1), None);
    assert_eq!(s.signer_entry(0).unwrap().count, 1);
    assert_eq!(s.signer_entry(2).unwrap().count, 1);
}

#[test]
fn full_rotation_replaces_every_signer_and_keeps_the_rule() {
    let s = Setup::new();
    let policy = s.e.register(MockPolicyContract, ());
    let mut policies = Map::new(&s.e);
    policies.set(policy.clone(), Val::from_void().into());
    let rule = s.add_rule(&s.passkeys(1..5), &policies);

    let ids = s.reconcile(rule.id, &s.passkeys(11..15));

    assert_eq!(ids, vec![&s.e, 4, 5, 6, 7]);
    // 4 × (deregistered + removed), then 4 × (registered + added)
    assert_eq!(s.event_count(), 16);
    for old in 0..4 {
        assert_eq!(s.signer_entry(old), None);
    }
    for new in 4..8 {
        assert_eq!(s.signer_entry(new).unwrap().count, 1);
    }

    let after = s.rule(rule.id);
    assert_eq!(after.id, rule.id);
    assert_eq!(after.name, rule.name);
    assert_eq!(after.context_type, rule.context_type);
    assert_eq!(after.policy_ids, rule.policy_ids);
    assert_eq!(after.policies, rule.policies);
    assert_eq!(after.signers, s.passkeys(11..15));
}

#[test]
fn permutation_rewrites_order_without_registry_changes() {
    let s = Setup::new();
    let rule = s.add_rule(&s.passkeys(1..4), &Map::new(&s.e));

    let ids = s.reconcile(rule.id, &vec![&s.e, s.passkey(3), s.passkey(1), s.passkey(2)]);

    assert_eq!(ids, vec![&s.e, 2, 0, 1]);
    assert_eq!(s.event_count(), 0);
    for id in 0..3 {
        assert_eq!(s.signer_entry(id).unwrap().count, 1);
    }
}

#[test]
fn swap_at_the_signer_limit() {
    let s = Setup::new();
    let full = s.passkeys(0..MAX_SIGNERS as u8);
    let rule = s.add_rule(&full, &Map::new(&s.e));

    // Adding before removing would need MAX_SIGNERS + 1 slots.
    let client = MockAccountClient::new(&s.e, &s.account);
    assert_eq!(
        client.try_add(&rule.id, &s.passkey(100)).err().unwrap().unwrap(),
        soroban_sdk::Error::from_contract_error(3010),
    );

    let mut swapped = full.clone();
    swapped.set(0, s.passkey(100));
    let ids = s.reconcile(rule.id, &swapped);

    assert_eq!(ids.len(), MAX_SIGNERS);
    assert_eq!(ids.first().unwrap(), MAX_SIGNERS);
    assert_eq!(ids.slice(1..), rule.signer_ids.slice(1..));
    assert_eq!(s.rule(rule.id).signers, swapped);
}

#[test]
fn shared_signers_keep_their_registry_references() {
    let s = Setup::new();
    let shared = s.passkey(1);
    let rule0 = s.add_rule(&vec![&s.e, shared.clone(), s.passkey(2)], &Map::new(&s.e));
    let rule1 = s.add_rule(&vec![&s.e, shared.clone(), s.passkey(3)], &Map::new(&s.e));
    assert_eq!(s.signer_entry(0).unwrap().count, 2);

    // Rule 0 drops the shared signer and picks up rule 1's other signer.
    let ids = s.reconcile(rule0.id, &vec![&s.e, s.passkey(2), s.passkey(3)]);

    assert_eq!(ids, vec![&s.e, 1, 2]);
    // Only membership events: both signers stay registered.
    let events = s.e.events().all();
    assert_eq!(events.events().len(), 2);
    assert_eq!(
        events.events().first().unwrap(),
        &SignerRemoved { context_rule_id: rule0.id, signer_id: 0 }.to_xdr(&s.e, &s.account),
    );
    assert_eq!(
        events.events().get(1).unwrap(),
        &SignerAdded { context_rule_id: rule0.id, signer_id: 2 }.to_xdr(&s.e, &s.account),
    );
    assert_eq!(s.signer_entry(0).unwrap().count, 1);
    assert_eq!(s.signer_entry(2).unwrap().count, 2);
    assert_eq!(s.rule(rule1.id).signer_ids, rule1.signer_ids);
}

#[test]
fn rotation_leaves_spending_limit_state_untouched() {
    let s = Setup::new();
    let policy = s.e.register(SpendingLimitPolicy, ());
    let mut policies = Map::new(&s.e);
    policies.set(
        policy.clone(),
        SpendingLimitAccountParams { spending_limit: 1_000, period_ledgers: 100 }.into_val(&s.e),
    );
    let rule = s.add_rule(&s.passkeys(1..3), &policies);

    let policy_state = |s: &Setup| {
        s.e.as_contract(&policy, || {
            spending_limit::get_spending_limit_data(&s.e, rule.id, &s.account)
        })
    };
    let policy_entry = |s: &Setup| -> PolicyEntry {
        s.e.as_contract(&s.account, || {
            s.e.storage().persistent().get(&SmartAccountStorageKey::PolicyData(0)).unwrap()
        })
    };
    let state_before = policy_state(&s);
    let entry_before = policy_entry(&s);

    s.reconcile(rule.id, &s.passkeys(5..7));

    assert_eq!(policy_state(&s), state_before);
    assert_eq!(policy_entry(&s), entry_before);
    assert_eq!(s.rule(rule.id).policy_ids, rule.policy_ids);
}

#[test]
fn no_events_variant_changes_storage_identically() {
    let run = |quiet: bool| {
        let s = Setup::new();
        let shared = s.passkey(1);
        let rule = s.add_rule(&s.passkeys(1..5), &Map::new(&s.e));
        s.add_rule(&vec![&s.e, shared], &Map::new(&s.e));
        let desired = vec![&s.e, s.passkey(4), s.passkey(1), s.passkey(9)];
        let ids = s.e.as_contract(&s.account, || {
            if quiet {
                reconcile_signers_no_events(&s.e, rule.id, &desired)
            } else {
                reconcile_signers(&s.e, rule.id, &desired)
            }
        });
        (ids.len(), s.event_count(), s.ledger())
    };

    let (default_ids, default_events, default_ledger) = run(false);
    let (quiet_ids, quiet_events, quiet_ledger) = run(true);

    assert_eq!(default_ids, quiet_ids);
    // 2 × (deregistered + removed) + (registered + added)
    assert_eq!(default_events, 6);
    assert_eq!(quiet_events, 0);
    assert_eq!(default_ledger, quiet_ledger);
}

/// Each rejected call must fail and leave every ledger entry as it was.
fn assert_rejected(s: &Setup, id: u32, signers: &Vec<Signer>, error: u32) {
    let before = s.ledger();
    let client = MockAccountClient::new(&s.e, &s.account);

    let result = client.try_reconcile(&id, signers);

    assert_eq!(
        result.err().unwrap().unwrap(),
        soroban_sdk::Error::from_contract_error(error),
        "expected error #{error}",
    );
    assert_eq!(s.ledger(), before);
}

#[test]
fn rejects_exact_duplicate() {
    let s = Setup::new();
    let rule = s.add_rule(&s.passkeys(1..3), &Map::new(&s.e));
    assert_rejected(&s, rule.id, &vec![&s.e, s.passkey(1), s.passkey(5), s.passkey(5)], 3007);
}

#[test]
fn rejects_canonical_duplicate() {
    let s = Setup::new();
    let rule = s.add_rule(&s.passkeys(1..3), &Map::new(&s.e));
    let same_key = s.passkey_with_credential(1, 7);
    assert_rejected(&s, rule.id, &vec![&s.e, s.passkey(1), same_key], 3007);
}

#[test]
fn rejects_over_the_signer_limit() {
    let s = Setup::new();
    let rule = s.add_rule(&s.passkeys(1..3), &Map::new(&s.e));
    assert_rejected(&s, rule.id, &s.passkeys(0..MAX_SIGNERS as u8 + 1), 3010);
}

#[test]
fn rejects_empty_set_without_policies() {
    let s = Setup::new();
    let rule = s.add_rule(&s.passkeys(1..3), &Map::new(&s.e));
    assert_rejected(&s, rule.id, &Vec::new(&s.e), 3004);
}

#[test]
fn allows_empty_set_with_policies() {
    let s = Setup::new();
    let policy = s.e.register(MockPolicyContract, ());
    let mut policies = Map::new(&s.e);
    policies.set(policy, Val::from_void().into());
    let rule = s.add_rule(&s.passkeys(1..3), &policies);

    assert_eq!(s.reconcile(rule.id, &Vec::new(&s.e)).len(), 0);
    assert_eq!(s.signer_entry(0), None);
    assert_eq!(s.signer_entry(1), None);
}

#[test]
fn rejects_oversized_key() {
    let s = Setup::new();
    let rule = s.add_rule(&s.passkeys(1..3), &Map::new(&s.e));
    let big = Signer::External(s.verifier.clone(), Bytes::from_array(&s.e, &[1; 257]));
    assert_rejected(&s, rule.id, &vec![&s.e, s.passkey(1), big], 3013);
}

#[test]
fn rejects_unknown_rule() {
    let s = Setup::new();
    s.add_rule(&s.passkeys(1..3), &Map::new(&s.e));
    assert_rejected(&s, 7, &s.passkeys(1..3), 3000);
}

/// `reconcile_signers` restates the count checks of
/// `validate_signers_and_policies` because the joining signers have no IDs
/// yet. Both must accept and reject the same signer and policy counts.
#[test]
fn count_checks_match_validate_signers_and_policies() {
    for with_policy in [false, true] {
        for count in [0, 1, MAX_SIGNERS - 1, MAX_SIGNERS, MAX_SIGNERS + 1] {
            let s = Setup::new();
            let client = MockAccountClient::new(&s.e, &s.account);
            let mut policies = Map::new(&s.e);
            if with_policy {
                policies.set(s.e.register(MockPolicyContract, ()), Val::from_void().into());
            }
            let rule = s.add_rule(&s.passkeys(1..3), &policies);

            let expected =
                client.try_validate(&count, &(with_policy as u32)).err().map(|e| e.unwrap());
            let actual = client
                .try_reconcile(&rule.id, &s.passkeys(100..100 + count as u8))
                .err()
                .map(|e| e.unwrap());

            assert_eq!(actual, expected, "{count} signers, policy: {with_policy}");
        }
    }
}
