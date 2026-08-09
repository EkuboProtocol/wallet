//! How every non-text value this database stores is encoded, in one place.
//!
//! A hash, an address, a signature, and a signed envelope are byte strings, so
//! they are stored as `BLOB` rather than as hex text. That is not primarily
//! about size. A `TEXT` column can only be constrained by shape — the check
//! this replaced, `address = lower(address) AND length(address) = 42`, admits
//! `0xzzzz…` because `lower()` says nothing about hex — so "this column holds
//! an address" was a claim the schema could not make, which is why the read
//! path re-derived it and needed a fallback for when it turned out false. A
//! `BLOB` column of exactly 20 bytes *is* an address: there is no 20-byte
//! string that is not one, decoding cannot fail, and the fallback has nothing
//! left to do.
//!
//! Moments are stored as milliseconds since the Unix epoch. RFC 3339 text
//! sorted correctly only by an accident of ASCII — `+` (0x2B) precedes `.`
//! (0x2E) precedes the digits, so a whole second sorted ahead of its own
//! fractions — and any writer spelling UTC as `Z` rather than `+00:00` would
//! have broken both the `ORDER BY created_at` indexes and the several places
//! that compare a re-formatted timestamp to claim a lease or to consume the
//! exact row a human reviewed. An integer compares as itself.
//!
//! The orphan rule is why these are wrappers: `Address` and `DateTime` are
//! foreign types and rusqlite's conversion traits are foreign traits, so the
//! encoding has to hang off something local. Everything binds through [`Blob`]
//! or [`Millis`] and reads back through [`RowExt`], so no call site spells out
//! an encoding and no two of them can disagree.

use alloy::primitives::{Address, B256, Bytes};
use chrono::{DateTime, SubsecRound, TimeZone, Utc};
use rusqlite::{
    Result as SqlResult,
    types::{FromSql, FromSqlError, FromSqlResult, ToSql, ToSqlOutput, ValueRef},
};
use std::borrow::Cow;

/// A value that is stored as its own bytes.
pub trait SqlBytes: Sized {
    /// The bytes to store. Borrowed for everything with a byte representation
    /// already in memory, which is everything but the integer below.
    fn to_sql_bytes(&self) -> Cow<'_, [u8]>;

    /// Rebuild from exactly the bytes a column holds. The error names the
    /// width that was expected, so a corrupt row says what it should have
    /// been rather than only that it was refused.
    fn from_sql_bytes(bytes: &[u8]) -> Result<Self, String>;
}

macro_rules! fixed_width_bytes {
    ($type:ty, $noun:literal, $width:literal) => {
        impl SqlBytes for $type {
            fn to_sql_bytes(&self) -> Cow<'_, [u8]> {
                Cow::Borrowed(self.as_slice())
            }

            fn from_sql_bytes(bytes: &[u8]) -> Result<Self, String> {
                <$type>::try_from(bytes).map_err(|_| {
                    format!("stored {} is {} bytes, not {}", $noun, bytes.len(), $width)
                })
            }
        }
    };
}

fixed_width_bytes!(Address, "address", 20);
fixed_width_bytes!(B256, "32-byte hash", 32);

/// Exact-width byte strings with no alloy type of their own, such as a 65-byte
/// signature. `N` is part of the type, so a caller cannot ask for the wrong
/// width.
impl<const N: usize> SqlBytes for [u8; N] {
    fn to_sql_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self)
    }

    fn from_sql_bytes(bytes: &[u8]) -> Result<Self, String> {
        Self::try_from(bytes).map_err(|_| format!("stored value is {} bytes, not {N}", bytes.len()))
    }
}

/// Variable-length byte strings: signed envelopes and message bodies.
impl SqlBytes for Bytes {
    fn to_sql_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self.as_ref())
    }

    fn from_sql_bytes(bytes: &[u8]) -> Result<Self, String> {
        Ok(Self::copy_from_slice(bytes))
    }
}

/// A 128-bit number, big-endian so that blob ordering is numeric ordering.
///
/// Wei-denominated gas prices do not fit `SQLite`'s signed 64-bit `INTEGER`, and
/// decimal text would reintroduce exactly the "sorts as text" problem the
/// timestamps had.
impl SqlBytes for u128 {
    fn to_sql_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(self.to_be_bytes().to_vec())
    }

    fn from_sql_bytes(bytes: &[u8]) -> Result<Self, String> {
        <[u8; 16]>::try_from(bytes)
            .map(Self::from_be_bytes)
            .map_err(|_| format!("stored 128-bit value is {} bytes, not 16", bytes.len()))
    }
}

/// Binds any [`SqlBytes`] value as the `BLOB` it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Blob<T>(pub T);

impl<T: SqlBytes> ToSql for Blob<T> {
    fn to_sql(&self) -> SqlResult<ToSqlOutput<'_>> {
        Ok(match self.0.to_sql_bytes() {
            Cow::Borrowed(bytes) => ToSqlOutput::Borrowed(ValueRef::Blob(bytes)),
            Cow::Owned(bytes) => ToSqlOutput::Owned(bytes.into()),
        })
    }
}

impl<T: SqlBytes> FromSql for Blob<T> {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        T::from_sql_bytes(value.as_blob()?)
            .map(Self)
            .map_err(|message| FromSqlError::Other(message.into()))
    }
}

/// Binds a moment as milliseconds since the Unix epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Millis(pub DateTime<Utc>);

impl ToSql for Millis {
    fn to_sql(&self) -> SqlResult<ToSqlOutput<'static>> {
        Ok(ToSqlOutput::Owned(self.0.timestamp_millis().into()))
    }
}

impl FromSql for Millis {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        let millis = value.as_i64()?;
        Utc.timestamp_millis_opt(millis)
            .single()
            .map(Self)
            .ok_or_else(|| {
                FromSqlError::Other(format!("stored timestamp {millis} is not a moment").into())
            })
    }
}

/// The current moment at the precision the database keeps.
///
/// Every stored timestamp goes through here rather than through `Utc::now`
/// directly, so a value held in memory equals the value that comes back out.
/// A reviewed proposal is consumed by matching the moment it was proposed, and
/// truncating at this boundary rather than silently inside the column keeps
/// that comparison exact.
///
/// The cost is that two events within one millisecond share a name, so a
/// moment from here is not usable as a generation. The pending-transaction
/// lifecycle used to name its leases with `updated_at` and does not any more:
/// it has a `generation` column, incremented by every write, precisely because
/// a name that can repeat let a stale replacement verdict land on a lease
/// taken since. Nothing else here is a deadline — no status is time-derived,
/// by design — and the proposal comparison is guarded by the review's own
/// state as well.
#[must_use]
pub fn now() -> DateTime<Utc> {
    Utc::now().trunc_subsecs(3)
}

/// Reads the encodings above back out of a row without naming them at the call
/// site.
pub trait RowExt {
    /// The `BLOB` at `index`, decoded.
    fn blob<T: SqlBytes>(&self, index: usize) -> SqlResult<T>;

    /// The nullable `BLOB` at `index`, decoded.
    fn blob_opt<T: SqlBytes>(&self, index: usize) -> SqlResult<Option<T>>;

    /// The epoch-millisecond `INTEGER` at `index`, as a moment.
    fn time(&self, index: usize) -> SqlResult<DateTime<Utc>>;

    /// The nullable epoch-millisecond `INTEGER` at `index`, as a moment.
    fn time_opt(&self, index: usize) -> SqlResult<Option<DateTime<Utc>>>;
}

impl RowExt for rusqlite::Row<'_> {
    fn blob<T: SqlBytes>(&self, index: usize) -> SqlResult<T> {
        self.get::<_, Blob<T>>(index).map(|blob| blob.0)
    }

    fn blob_opt<T: SqlBytes>(&self, index: usize) -> SqlResult<Option<T>> {
        Ok(self.get::<_, Option<Blob<T>>>(index)?.map(|blob| blob.0))
    }

    fn time(&self, index: usize) -> SqlResult<DateTime<Utc>> {
        self.get::<_, Millis>(index).map(|millis| millis.0)
    }

    fn time_opt(&self, index: usize) -> SqlResult<Option<DateTime<Utc>>> {
        Ok(self.get::<_, Option<Millis>>(index)?.map(|millis| millis.0))
    }
}

#[cfg(test)]
#[path = "sql_test.rs"]
mod tests;
