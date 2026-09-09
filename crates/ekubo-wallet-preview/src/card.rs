//! Length-constrained realization of a whole plan. Calls retain their order;
//! supporting permissions use less space than the action they enable. Concrete
//! values come from labeled evidence, never from generated numeric text.

use std::fmt::Write as _;

use crate::{CallSummary, PlanDocument, TransactionClass, TransactionPreview};

/// Preferred card width in Unicode scalar values. Shorter complete summaries
/// are preferable to padding; the hard limit also applies to fallbacks.
pub const TARGET_CHARS: usize = 80;
pub const MAX_CHARS: usize = 100;

#[derive(Clone, Debug)]
struct Phrase {
    brief: String,
    detail: String,
    priority: u16,
    salience: f32,
    permission: bool,
    uncertain: bool,
}

/// Compose the model's call-level readings into a short, ordered plan summary.
/// The search spends the available character budget on the principal action
/// before supporting actions. It never slices a finished sentence or a value.
#[must_use]
pub fn summarize(document: &PlanDocument, predictions: &[TransactionPreview]) -> String {
    if document.calls.is_empty() {
        return "No calls".into();
    }
    let salience = crate::focus::scores(
        &predictions
            .iter()
            .zip(&document.calls)
            .map(|(p, call)| {
                if call.description.is_some() {
                    p.class
                } else {
                    TransactionClass::Unrecognized
                }
            })
            .collect::<Vec<_>>(),
    );
    let phrases: Vec<_> = document
        .calls
        .iter()
        .enumerate()
        .map(|(index, call)| {
            let mut p = phrase(call, predictions.get(index));
            p.salience = salience.get(index).copied().unwrap_or_default();
            p
        })
        .collect();
    let phrases = bind_permissions(document, phrases);
    let phrases = coalesce(&phrases);
    let baseline: Vec<_> = phrases.iter().map(|phrase| phrase.brief.clone()).collect();
    if length(&join(&baseline)) > MAX_CHARS {
        return overview(&phrases, document.calls.len());
    }
    let mut chosen = baseline;
    let mut order: Vec<_> = (0..phrases.len()).collect();
    // Later substantive actions tend to be the destination of a workflow:
    // claim -> swap -> deposit. This changes detail allocation, never order.
    order.sort_by(|a, b| {
        phrases[*b]
            .salience
            .total_cmp(&phrases[*a].salience)
            .then_with(|| phrases[*b].priority.cmp(&phrases[*a].priority))
            .then(b.cmp(a))
    });
    for limit in [TARGET_CHARS, MAX_CHARS] {
        for index in &order {
            let mut candidate = chosen.clone();
            candidate[*index].clone_from(&phrases[*index].detail);
            if length(&join(&candidate)) <= limit {
                chosen = candidate;
            }
        }
        // Do not exceed the target merely to add protocol decoration.
        if chosen
            .iter()
            .zip(&phrases)
            .any(|(text, phrase)| text != &phrase.brief)
        {
            break;
        }
    }
    join(&chosen)
}

fn bind_permissions(document: &PlanDocument, mut phrases: Vec<Phrase>) -> Vec<Phrase> {
    for (index, call) in document.calls.iter().enumerate() {
        if !phrases[index].permission || phrases[index].brief == "revoke approval" {
            continue;
        }
        let Some((spender, amount)) = approval_arguments(call) else {
            continue;
        };
        let next = document.calls[index + 1..].iter().find(|next| {
            compatible_chain(call, next)
                && crate::evidence::same_address_or_label(
                    &spender,
                    next.evidence
                        .as_ref()
                        .map_or(next.target.as_str(), |e| e.to.as_str()),
                )
        });
        let related = next.is_some_and(|next| {
            crate::evidence::same_address_or_label(
                &spender,
                next.evidence
                    .as_ref()
                    .map_or(next.target.as_str(), |e| e.to.as_str()),
            )
        });
        let exact = related
            && next.is_some_and(|next| compatible_input_asset(call, next))
            && next
                .and_then(|next| field(next, &["amount in", "input amount", "amountin", "amount"]))
                .is_some_and(|input| input == amount);
        if exact && phrases[index].brief == "approve" {
            phrases[index].detail = "approve".into();
        } else if !related {
            let base = if phrases[index].brief == "approve" {
                format!("approve {amount}")
            } else {
                phrases[index].detail.clone()
            };
            let text = format!("{base} to {}", short_target(&spender));
            // A separate spender must survive optional detail removal.
            phrases[index].brief.clone_from(&text);
            phrases[index].detail = text;
        } else if phrases[index].brief == "approve" {
            let text = format!("approve {amount}");
            phrases[index].brief.clone_from(&text);
            phrases[index].detail = text;
        }
    }
    phrases
}

// A matching display symbol or router address cannot override contradictory
// execution evidence. Missing metadata keeps the decoded-reading fallback.
fn compatible_chain(approval: &CallSummary, action: &CallSummary) -> bool {
    match (&approval.evidence, &action.evidence) {
        (Some(a), Some(b)) => a.chain_id == b.chain_id,
        _ => true,
    }
}

fn compatible_input_asset(approval: &CallSummary, action: &CallSummary) -> bool {
    let Some(token) = crate::evidence::address(
        approval
            .evidence
            .as_ref()
            .map_or(&approval.target, |e| &e.to),
    ) else {
        return true;
    };
    action.details.iter().all(|line| {
        let Some((label, value)) = line.split_once(':') else {
            return true;
        };
        if ![
            "token in",
            "input token",
            "tokenin",
            "asset",
            "amount in",
            "input amount",
            "amountin",
            "amount",
        ]
        .contains(&label.trim().to_lowercase().as_str())
        {
            return true;
        }
        crate::evidence::address(value).is_none_or(|input| input.eq_ignore_ascii_case(token))
    })
}

fn approval_arguments(call: &CallSummary) -> Option<(String, String)> {
    let description = call.description.as_deref()?;
    let (spender, amount) = description
        .strip_prefix("approve spender ")?
        .split_once(" for ")?;
    let spender = call
        .evidence
        .as_ref()
        .and_then(crate::evidence::approval_spender)
        .unwrap_or_else(|| spender.trim().into());
    Some((spender, compact(amount)))
}

fn short_target(text: &str) -> String {
    if text.len() == 42
        && text.starts_with("0x")
        && text[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        format!("{}…{}", &text[..8], &text[36..])
    } else {
        compact(text)
    }
}

fn length(text: &str) -> usize {
    text.chars().count()
}

fn phrase(call: &CallSummary, prediction: Option<&TransactionPreview>) -> Phrase {
    let Some(description) = call
        .description
        .as_deref()
        .filter(|text| !text.trim().is_empty())
    else {
        return Phrase {
            brief: "unknown call".into(),
            detail: if crate::slots::is_zero_value(&call.native_value) {
                tentative_hint(call, prediction)
            } else {
                format!("unknown call sending {}", compact(&call.native_value))
            },
            priority: 100,
            salience: 0.0,
            permission: false,
            uncertain: true,
        };
    };
    let (protocol, action) = description
        .split_once(" — ")
        .map_or((None, description), |(protocol, action)| {
            (Some(protocol), action)
        });
    let action = action.trim();
    let lower = action.to_lowercase();
    if let Some(permission) = permission(call, &lower) {
        return permission;
    }
    let class = prediction.map_or(TransactionClass::Unrecognized, |p| p.class);
    let (brief, priority) = action_phrase(action, &lower, class);
    let mut detail = brief.clone();
    if lower.starts_with("swap") || lower.starts_with("sell") {
        if let Some(amount) = field(
            call,
            &[
                "amount in",
                "input amount",
                "amount to sell",
                "sell amount",
                "amountin",
            ],
        ) {
            detail = format!("{brief} {amount}");
        } else if let Some(token) =
            field(call, &["token in", "input token", "sell token", "tokenin"])
        {
            detail = format!("{brief} {token}");
        }
        if let Some(token) = field(
            call,
            &["token out", "output token", "buy token", "tokenout"],
        ) {
            let _ = write!(detail, " for {token}");
        }
    } else if supports_amount(&lower) {
        if let Some(amount) = field(
            call,
            &[
                "amount",
                "assets",
                "shares",
                "amount to deposit",
                "amount to withdraw",
            ],
        ) {
            detail = format!("{brief} {amount}");
        } else if lower.starts_with("stake") && !crate::slots::is_zero_value(&call.native_value) {
            detail = format!("{brief} {}", compact(&call.native_value));
        }
    }
    if detail == brief
        && let Some(protocol) = protocol.filter(|name| length(name) <= 30)
    {
        detail = format!("{brief} on {}", compact(protocol));
    }
    let mut brief = brief;
    if let Some(recipient) = field(call, &["recipient", "receiver", "to"])
        && !call
            .evidence
            .as_ref()
            .is_some_and(|e| crate::evidence::same_address_or_label(&recipient, &e.from))
        && !recipient.to_lowercase().contains("your account")
    {
        let destination = short_target(&recipient);
        let _ = write!(brief, " to {destination}");
        let _ = write!(detail, " to {destination}");
    }
    Phrase {
        brief,
        detail,
        priority,
        salience: 0.0,
        permission: false,
        uncertain: false,
    }
}

fn tentative_hint(call: &CallSummary, prediction: Option<&TransactionPreview>) -> String {
    let aliases: &[&str] = match prediction.map(|p| p.class) {
        Some(TransactionClass::Swap) => &["swap"],
        Some(TransactionClass::Supply) => &["deposit", "supply"],
        Some(TransactionClass::Transfer) => &["transfer"],
        Some(TransactionClass::Withdraw) => &["withdraw", "redeem"],
        Some(TransactionClass::Stake) => &["stake"],
        Some(TransactionClass::Claim) => &["claim"],
        _ => &[],
    };
    let supported = call.evidence.as_ref().is_some_and(|evidence| {
        evidence.abi.iter().any(|abi| {
            let name = abi
                .signature
                .split('(')
                .next()
                .unwrap_or_default()
                .to_lowercase();
            aliases.iter().any(|alias| name.starts_with(alias))
        })
    });
    if supported {
        format!("unknown call (possible {})", aliases[0])
    } else {
        "unknown call".into()
    }
}

fn supports_amount(action: &str) -> bool {
    [
        "supply", "deposit", "withdraw", "redeem", "repay", "borrow", "stake", "unstake",
        "cooldown",
    ]
    .iter()
    .any(|prefix| action.starts_with(prefix))
}

fn action_phrase(action: &str, lower: &str, class: TransactionClass) -> (String, u16) {
    let known = [
        ("swap exact input", "swap", 60),
        ("swap tokens", "swap", 60),
        ("cooldown shares", "start cooldown", 70),
        ("cooldown assets", "start cooldown", 70),
        ("stake eth", "stake", 70),
        ("swap", "swap", 60),
        ("sell", "sell", 60),
        ("supply", "deposit", 70),
        ("deposit", "deposit", 70),
        ("claim rewards", "claim rewards", 40),
        ("claim", "claim", 40),
        ("cooldown", "start cooldown", 70),
        ("remove liquidity", "remove liquidity", 70),
        ("add liquidity", "add liquidity", 70),
        ("withdraw", "withdraw", 70),
        ("redeem", "redeem", 70),
        ("repay", "repay", 70),
        ("borrow", "borrow", 70),
        ("unstake", "unstake", 70),
        ("stake", "stake", 70),
        ("unwrap", "unwrap", 40),
        ("wrap", "wrap", 40),
    ];
    if let Some((_, text, priority)) = known.iter().find(|(phrase, _, _)| lower == *phrase) {
        return ((*text).into(), *priority);
    }
    // A learned category contributes salience, but cannot turn an unfamiliar
    // decoded action into a different operation just to fit a template.
    let priority = match class {
        TransactionClass::Approval | TransactionClass::Revocation => 20,
        TransactionClass::Transfer | TransactionClass::WrapUnwrap | TransactionClass::Claim => 40,
        _ => 60,
    };
    (
        lowercase_first(&shorten_addresses(&compact(action))),
        priority,
    )
}

fn permission(call: &CallSummary, action: &str) -> Option<Phrase> {
    let operator = action.starts_with("setapprovalforall");
    let revoke = (action.starts_with("revoke ")
        && (action.contains("allowance") || action.contains("approval")))
        || (operator && (action.contains("revoke operator") || action.ends_with("approved false")));
    let approve = action.starts_with("approve ") || action == "approve" || (operator && !revoke);
    if !revoke && !approve {
        return None;
    }
    let unlimited = call
        .evidence
        .as_ref()
        .is_some_and(crate::evidence::unlimited_approval)
        || action.contains("unlimited")
        || call
            .warnings
            .iter()
            .any(|w| w.to_lowercase().contains("unlimited"));
    let brief = if revoke {
        "revoke approval"
    } else if operator {
        "approve all tokens"
    } else if unlimited {
        "unlimited approve"
    } else {
        "approve"
    };
    let token = field(call, &["token", "asset", "approval token"]).or_else(|| {
        let (_, amount) = call.description.as_deref()?.rsplit_once(" for ")?;
        amount.split_once(' ').map(|(_, token)| compact(token))
    });
    let detail = token
        .filter(|_| !operator && !revoke)
        .map_or_else(|| brief.into(), |token| format!("{brief} {token}"));
    Some(Phrase {
        brief: brief.into(),
        detail,
        priority: if unlimited || operator { 90 } else { 20 },
        salience: 0.0,
        permission: true,
        uncertain: false,
    })
}

/// Match whole normalized labels. A minimum output is never an input amount;
/// duplicate conflicting labels are ambiguous and therefore not named.
fn field(call: &CallSummary, labels: &[&str]) -> Option<String> {
    let mut values = call
        .details
        .iter()
        .filter_map(|line| {
            let (label, value) = line.split_once(':')?;
            labels
                .contains(&label.trim().to_lowercase().as_str())
                .then(|| compact(value))
        })
        .filter(|value| !value.is_empty());
    let first = values.next()?;
    values.all(|value| value == first).then_some(first)
}

fn compact(text: &str) -> String {
    let text = text.trim();
    // Token display labels may include their full address in parentheses.
    // Remove only a syntactically complete address annotation, not arbitrary
    // parenthesized caveats or units.
    let text = text
        .rsplit_once(" (0x")
        .filter(|(_, suffix)| {
            suffix.len() == 41
                && suffix.ends_with(')')
                && suffix[..40].bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        .map_or(text, |(label, _)| label);
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn shorten_addresses(text: &str) -> String {
    let mut result = String::new();
    let mut remaining = text;
    while let Some(address) = crate::evidence::address(remaining) {
        let Some((before, after)) = remaining.split_once(address) else {
            break;
        };
        result.push_str(before);
        result.push_str(&short_target(address));
        remaining = after;
    }
    result.push_str(remaining);
    result
}

fn lowercase_first(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_lowercase().collect::<String>() + chars.as_str()
    })
}

fn join(phrases: &[String]) -> String {
    let text = match phrases {
        [] => String::new(),
        [only] => only.clone(),
        [first, second] if second.starts_with("revoke ") => format!("{first}, then {second}"),
        [first, second] => format!("{first} and {second}"),
        _ => format!(
            "{}, and {}",
            phrases[..phrases.len() - 1].join(", "),
            phrases.last().expect("nonempty")
        ),
    };
    let mut chars = text.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().collect::<String>() + chars.as_str()
    })
}

fn coalesce(phrases: &[Phrase]) -> Vec<Phrase> {
    let mut result: Vec<Phrase> = Vec::new();
    let mut cursor = 0;
    while cursor < phrases.len() {
        let phrase = &phrases[cursor];
        let mut end = cursor + 1;
        while end < phrases.len() && phrases[end].brief == phrase.brief && !phrase.permission {
            end += 1;
        }
        let mut combined = phrase.clone();
        if end - cursor > 1 {
            combined.brief = format!("{} ×{}", phrase.brief, end - cursor);
            combined.detail = if phrases[cursor..end]
                .iter()
                .all(|p| p.detail == phrase.detail)
            {
                format!("{} ×{}", phrase.detail, end - cursor)
            } else {
                combined.brief.clone()
            };
        }
        result.push(combined);
        cursor = end;
    }
    result
}

fn overview(phrases: &[Phrase], count: usize) -> String {
    let noun = if count == 1 { "call" } else { "calls" };
    // When the ordered action sequence itself will not fit, explicitly mark
    // incompleteness. Never display just the first calls as the whole plan.
    let unlimited = phrases
        .iter()
        .any(|p| p.brief.contains("unlimited approve"));
    let operator = phrases
        .iter()
        .any(|p| p.brief.contains("approve all tokens"));
    let unknown = phrases.iter().any(|p| p.uncertain);
    if unknown && (unlimited || operator) {
        let permission = if unlimited && operator {
            "unlimited/operator approvals"
        } else if unlimited {
            "unlimited approvals"
        } else {
            "operator approvals"
        };
        return format!("{count} {noun} with {permission} and unknown calls; review full plan");
    }
    let important = phrases
        .iter()
        .enumerate()
        .max_by_key(|(index, phrase)| (phrase.uncertain, phrase.priority, *index));
    if let Some((_, phrase)) = important {
        for detail in [&phrase.detail, &phrase.brief] {
            let text = format!("{count} {noun} including {detail}; review full plan");
            if length(&text) <= MAX_CHARS {
                return text;
            }
        }
    }
    format!("{count} {noun}; review full plan")
}

#[cfg(test)]
#[path = "card_test.rs"]
mod tests;
