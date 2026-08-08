use super::*;
use alloy::primitives::{address, b256};
use rusqlite::Connection;

/// A table with one column of each encoding, so a round trip exercises the
/// same `ToSql`/`FromSql` path the real schema uses.
fn scratch() -> Connection {
    let connection = Connection::open_in_memory().expect("in-memory database");
    connection
        .execute_batch(
            "CREATE TABLE probe (
                 id INTEGER PRIMARY KEY,
                 address BLOB CHECK (address IS NULL OR length(address) = 20),
                 hash BLOB CHECK (hash IS NULL OR length(hash) = 32),
                 payload BLOB,
                 signature BLOB CHECK (signature IS NULL OR length(signature) = 65),
                 price BLOB CHECK (price IS NULL OR length(price) = 16),
                 at INTEGER
             ) STRICT",
        )
        .expect("schema");
    connection
}

#[test]
fn every_encoding_round_trips() {
    let connection = scratch();
    let address = address!("0x1111111111111111111111111111111111111111");
    let hash = b256!("0x2222222222222222222222222222222222222222222222222222222222222222");
    let payload = Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]);
    let signature = [7_u8; 65];
    let price: u128 = 12_345_678_901_234_567_890;
    let at = now();
    connection
        .execute(
            "INSERT INTO probe(id, address, hash, payload, signature, price, at)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                Blob(address),
                Blob(hash),
                Blob(payload.clone()),
                Blob(signature),
                Blob(price),
                Millis(at)
            ],
        )
        .expect("insert");
    let read = connection
        .query_row("SELECT * FROM probe WHERE id = 1", [], |row| {
            Ok((
                row.blob::<Address>(1)?,
                row.blob::<B256>(2)?,
                row.blob::<Bytes>(3)?,
                row.blob::<[u8; 65]>(4)?,
                row.blob::<u128>(5)?,
                row.time(6)?,
            ))
        })
        .expect("read");
    assert_eq!(read, (address, hash, payload, signature, price, at));
}

/// The point of the blob columns: what comes back is the exact bytes, and the
/// column is what a hex-text column could only claim to be.
#[test]
fn an_address_column_holds_exactly_twenty_bytes() {
    let connection = scratch();
    let refused = connection.execute(
        "INSERT INTO probe(id, address) VALUES (1, ?1)",
        rusqlite::params![Blob(Bytes::from_static(&[0_u8; 19]))],
    );
    assert!(refused.is_err(), "a 19-byte address must be refused");

    connection
        .execute(
            "INSERT INTO probe(id, address) VALUES (2, ?1)",
            rusqlite::params![Blob(address!("0x00000000000000000000000000000000000000ff"))],
        )
        .expect("a 20-byte address is accepted");
}

/// A blob of the wrong width fails on the way out, naming the width it should
/// have had, rather than being silently reinterpreted.
#[test]
fn a_mistyped_read_reports_the_width_it_wanted() {
    let connection = scratch();
    connection
        .execute(
            "INSERT INTO probe(id, payload) VALUES (1, ?1)",
            rusqlite::params![Blob(Bytes::from_static(&[1, 2, 3]))],
        )
        .expect("insert");
    let error = connection
        .query_row("SELECT payload FROM probe WHERE id = 1", [], |row| {
            row.blob::<B256>(0)
        })
        .expect_err("three bytes are not a hash");
    assert!(
        error.to_string().contains("3 bytes, not 32"),
        "unexpected error: {error}"
    );
}

/// Why the timestamps moved: as integers, ordering is numeric, so a moment
/// spelled a different way cannot sort into the wrong place. The RFC 3339
/// text these replaced sorted correctly only while every writer spelled UTC
/// as `+00:00`, and `Z` for the same instant sorted after all of them.
#[test]
fn moments_order_numerically() {
    let connection = scratch();
    let base = now();
    let later = base + chrono::TimeDelta::milliseconds(500);
    let latest = base + chrono::TimeDelta::seconds(1);
    for (id, moment) in [(1, later), (2, latest), (3, base)] {
        connection
            .execute(
                "INSERT INTO probe(id, at) VALUES (?1, ?2)",
                rusqlite::params![id, Millis(moment)],
            )
            .expect("insert");
    }
    let mut statement = connection
        .prepare("SELECT at FROM probe ORDER BY at")
        .expect("prepare");
    let ordered = statement
        .query_map([], |row| row.time(0))
        .expect("query")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("rows");
    assert_eq!(ordered, vec![base, later, latest]);
}

/// `now` truncates so that a value held in memory equals the value read back.
/// The compare-and-set writes that name a lease or a reviewed proposal by its
/// timestamp depend on that equality holding exactly.
#[test]
fn now_round_trips_without_losing_precision() {
    let connection = scratch();
    let moment = now();
    connection
        .execute(
            "INSERT INTO probe(id, at) VALUES (1, ?1)",
            rusqlite::params![Millis(moment)],
        )
        .expect("insert");
    let matched: i64 = connection
        .query_row(
            "SELECT count(*) FROM probe WHERE at = ?1",
            rusqlite::params![Millis(moment)],
            |row| row.get(0),
        )
        .expect("count");
    assert_eq!(matched, 1, "the stored moment must match itself");
    assert_eq!(moment.timestamp_subsec_nanos() % 1_000_000, 0);
}

/// Big-endian, so the byte ordering of two prices is their numeric ordering.
#[test]
fn prices_order_as_numbers() {
    let connection = scratch();
    for (id, price) in [(1_i64, u128::MAX), (2, 1), (3, u128::from(u64::MAX) + 1)] {
        connection
            .execute(
                "INSERT INTO probe(id, price) VALUES (?1, ?2)",
                rusqlite::params![id, Blob(price)],
            )
            .expect("insert");
    }
    let mut statement = connection
        .prepare("SELECT price FROM probe WHERE price IS NOT NULL ORDER BY price")
        .expect("prepare");
    let ordered = statement
        .query_map([], |row| row.blob::<u128>(0))
        .expect("query")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("rows");
    assert_eq!(ordered, vec![1, u128::from(u64::MAX) + 1, u128::MAX]);
}

#[test]
fn a_null_column_reads_as_absent() {
    let connection = scratch();
    connection
        .execute("INSERT INTO probe(id) VALUES (1)", [])
        .expect("insert");
    let read = connection
        .query_row("SELECT hash, at FROM probe WHERE id = 1", [], |row| {
            Ok((row.blob_opt::<B256>(0)?, row.time_opt(1)?))
        })
        .expect("read");
    assert_eq!(read, (None, None));
}
