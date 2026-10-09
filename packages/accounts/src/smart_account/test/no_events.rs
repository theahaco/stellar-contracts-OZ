extern crate std;

use soroban_sdk::{
    auth::Context,
    contract, contractimpl,
    testutils::{Address as _, Events},
    vec, Address, Bytes, Env, Event, Map, String, TryFromVal, Val, Vec,
};

use crate::{
    policies::Policy,
    smart_account::{
        storage::{
            add_context_rule, add_context_rule_no_events, add_policy, add_policy_no_events,
            add_signer, add_signer_no_events, batch_add_signer, batch_add_signer_no_events,
            get_context_rule, remove_context_rule, remove_context_rule_no_events, remove_policy,
            remove_policy_no_events, remove_signer, remove_signer_no_events,
            update_context_rule_name, update_context_rule_name_no_events,
            update_context_rule_valid_until, update_context_rule_valid_until_no_events,
            ContextRule, ContextRuleType, PolicyEntry, Signer, SmartAccountStorageKey,
        },
        ContextRuleAdded, PolicyRegistered, SignerRegistered,
    },
};

#[contract]
struct MockContract;

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
struct MockVerifierContract;

#[contractimpl]
impl MockVerifierContract {
    pub fn verify(_e: &Env, _hash: Bytes, _key_data: Val, _sig_data: Val) -> bool {
        true
    }

    pub fn canonicalize_key(e: &Env, key_data: Val) -> Bytes {
        Bytes::try_from_val(e, &key_data).unwrap()
    }

    pub fn batch_canonicalize_key(e: &Env, key_data: Vec<Val>) -> Vec<Bytes> {
        Vec::from_iter(e, key_data.iter().map(|key| Bytes::try_from_val(e, &key).unwrap()))
    }
}

/// A passkey-shaped external signer: 65-byte secp256r1 key plus a 16-byte
/// credential id.
fn passkey(e: &Env, verifier: &Address, seed: u8) -> Signer {
    Signer::External(verifier.clone(), Bytes::from_array(e, &[seed; 81]))
}

/// Runs every rule, signer and policy mutation once, through either the
/// default or the `_no_events` functions. After each step it records the
/// number of events published and the full set of ledger entries.
fn run(quiet: bool) -> std::vec::Vec<(u32, std::string::String)> {
    let e = Env::default();
    let account = e.register(MockContract, ());
    let verifier = e.register(MockVerifierContract, ());
    let policy_a = e.register(MockPolicyContract, ());
    let policy_b = e.register(MockPolicyContract, ());
    let policy_c = e.register(MockPolicyContract, ());
    let target = Address::generate(&e);
    let delegated = Signer::Delegated(Address::generate(&e));

    let mut steps = std::vec::Vec::new();
    let mut step = |f: &dyn Fn()| {
        e.as_contract(&account, f);
        let events = e.events().all().events().len() as u32;
        let entries = std::format!("{:?}", e.to_ledger_snapshot().ledger_entries);
        steps.push((events, entries));
    };

    let mut policies = Map::new(&e);
    policies.set(policy_a.clone(), Val::from_void().into());
    policies.set(policy_b.clone(), Val::from_void().into());
    let signers = vec![&e, passkey(&e, &verifier, 1), passkey(&e, &verifier, 2), delegated];
    let context_type = ContextRuleType::CallContract(target);
    let name = String::from_str(&e, "doc");
    step(&|| {
        if quiet {
            add_context_rule_no_events(&e, &context_type, &name, None, &signers, &policies);
        } else {
            add_context_rule(&e, &context_type, &name, None, &signers, &policies);
        }
    });

    let p3 = passkey(&e, &verifier, 3);
    step(&|| {
        if quiet {
            add_signer_no_events(&e, 0, &p3);
        } else {
            add_signer(&e, 0, &p3);
        }
    });

    let p4 = vec![&e, passkey(&e, &verifier, 4)];
    step(&|| {
        if quiet {
            batch_add_signer_no_events(&e, 0, &p4);
        } else {
            batch_add_signer(&e, 0, &p4);
        }
    });

    step(&|| {
        if quiet {
            add_policy_no_events(&e, 0, &policy_c, Val::from_void().into());
        } else {
            add_policy(&e, 0, &policy_c, Val::from_void().into());
        }
    });

    let renamed = String::from_str(&e, "renamed");
    step(&|| {
        if quiet {
            update_context_rule_name_no_events(&e, 0, &renamed);
        } else {
            update_context_rule_name(&e, 0, &renamed);
        }
    });

    let valid_until = Some(e.ledger().sequence() + 100);
    step(&|| {
        if quiet {
            update_context_rule_valid_until_no_events(&e, 0, valid_until);
        } else {
            update_context_rule_valid_until(&e, 0, valid_until);
        }
    });

    // passkey 3 was registered by `add_signer` above, so it is signer id 3
    step(&|| {
        let signer_id = get_context_rule(&e, 0).signer_ids.get_unchecked(3);
        if quiet {
            remove_signer_no_events(&e, 0, signer_id);
        } else {
            remove_signer(&e, 0, signer_id);
        }
    });

    step(&|| {
        let policy_id = get_context_rule(&e, 0).policy_ids.get_unchecked(2);
        if quiet {
            remove_policy_no_events(&e, 0, policy_id);
        } else {
            remove_policy(&e, 0, policy_id);
        }
    });

    // A second rule reusing an already registered signer and policy only
    // bumps their reference counts.
    let shared_signers = vec![&e, passkey(&e, &verifier, 1)];
    let mut shared_policies = Map::new(&e);
    shared_policies.set(policy_a.clone(), Val::from_void().into());
    let shared_type = ContextRuleType::Default;
    let shared_name = String::from_str(&e, "shared");
    step(&|| {
        if quiet {
            add_context_rule_no_events(
                &e,
                &shared_type,
                &shared_name,
                None,
                &shared_signers,
                &shared_policies,
            );
        } else {
            add_context_rule(
                &e,
                &shared_type,
                &shared_name,
                None,
                &shared_signers,
                &shared_policies,
            );
        }
    });

    for id in [1, 0] {
        step(&|| {
            if quiet {
                remove_context_rule_no_events(&e, id);
            } else {
                remove_context_rule(&e, id);
            }
        });
    }

    steps
}

#[test]
fn no_events_variants_change_storage_identically() {
    let default = run(false);
    let quiet = run(true);

    assert_eq!(default.len(), quiet.len());
    for (i, ((_, default_entries), (_, quiet_entries))) in
        default.iter().zip(quiet.iter()).enumerate()
    {
        assert_eq!(default_entries, quiet_entries, "ledger entries differ after step {i}");
    }
}

#[test]
fn no_events_variants_emit_nothing() {
    for (i, (events, _)) in run(true).iter().enumerate() {
        assert_eq!(*events, 0, "step {i} emitted events");
    }
}

#[test]
fn default_variants_still_emit_every_event() {
    let events: std::vec::Vec<u32> = run(false).iter().map(|(n, _)| *n).collect();
    assert_eq!(
        events,
        std::vec![
            6, // 3 signer_registered, 2 policy_registered, context_rule_added
            2, // signer_registered, signer_added
            2, // signer_registered, signer_added
            2, // policy_registered, policy_added
            1, // context_rule_meta_updated
            1, // context_rule_meta_updated
            2, // signer_deregistered, signer_removed
            2, // policy_deregistered, policy_removed
            1, // context_rule_added (signer and policy already registered)
            1, // context_rule_removed (signer and policy still referenced)
            7, // 4 signer_deregistered, 2 policy_deregistered, context_rule_removed
        ]
    );
}

#[test]
fn default_add_context_rule_events_unchanged() {
    let e = Env::default();
    let account = e.register(MockContract, ());
    let verifier = e.register(MockVerifierContract, ());
    let policy = e.register(MockPolicyContract, ());
    let signer = passkey(&e, &verifier, 1);
    let mut policies = Map::new(&e);
    policies.set(policy.clone(), Val::from_void().into());
    let name = String::from_str(&e, "doc");

    e.as_contract(&account, || {
        add_context_rule(
            &e,
            &ContextRuleType::Default,
            &name,
            None,
            &vec![&e, signer.clone()],
            &policies,
        );
    });

    let events = e.events().all();
    assert_eq!(events.events().len(), 3);
    assert_eq!(
        events.events().first().unwrap(),
        &SignerRegistered { signer_id: 0, signer }.to_xdr(&e, &account),
    );
    assert_eq!(
        events.events().get(1).unwrap(),
        &PolicyRegistered { policy_id: 0, policy }.to_xdr(&e, &account),
    );
    assert_eq!(
        events.events().get(2).unwrap(),
        &ContextRuleAdded {
            context_rule_id: 0,
            name,
            context_type: ContextRuleType::Default,
            valid_until: None,
            signer_ids: vec![&e, 0],
            policy_ids: vec![&e, 0],
        }
        .to_xdr(&e, &account),
    );
}

/// Exposes `add_policy` as an entry point so that a rejected call can be
/// observed through `try_` without unwinding the test.
#[contract]
struct MockAccount;

#[contractimpl]
impl MockAccount {
    pub fn add_policy(e: &Env, id: u32, policy: Address, quiet: bool) -> u32 {
        if quiet {
            add_policy_no_events(e, id, &policy, Val::from_void().into())
        } else {
            add_policy(e, id, &policy, Val::from_void().into())
        }
    }
}

/// `add_policy` registers the policy before its duplicate check, so a
/// rejected duplicate must not leave the registry refcount incremented.
#[test]
fn duplicate_add_policy_leaves_registry_unchanged() {
    for quiet in [false, true] {
        let e = Env::default();
        let account = e.register(MockAccount, ());
        let verifier = e.register(MockVerifierContract, ());
        let policy = e.register(MockPolicyContract, ());
        let mut policies = Map::new(&e);
        policies.set(policy.clone(), Val::from_void().into());
        let rule = e.as_contract(&account, || {
            add_context_rule(
                &e,
                &ContextRuleType::Default,
                &String::from_str(&e, "doc"),
                None,
                &vec![&e, passkey(&e, &verifier, 1)],
                &policies,
            )
        });
        let ledger = |e: &Env| {
            let entries = e.to_ledger_snapshot().ledger_entries;
            std::format!(
                "{:?}",
                entries.iter().map(|(key, (entry, _))| (key, entry)).collect::<std::vec::Vec<_>>()
            )
        };
        let before = ledger(&e);

        let result = MockAccountClient::new(&e, &account).try_add_policy(&rule.id, &policy, &quiet);

        assert_eq!(result.err().unwrap().unwrap(), soroban_sdk::Error::from_contract_error(3009));
        assert_eq!(ledger(&e), before);
        let entry: PolicyEntry = e.as_contract(&account, || {
            e.storage().persistent().get(&SmartAccountStorageKey::PolicyData(0)).unwrap()
        });
        assert_eq!(entry.count, 1);
    }
}
