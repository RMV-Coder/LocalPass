//! Formatting unix-millis timestamps as ISO 8601 UTC — *without* a date crate.
//!
//! `item list` / `search` show an `UPDATED` column, and the raw millis are
//! unreadable. We render `YYYY-MM-DD HH:MMZ` (minute precision, always UTC).
//!
//! # Why hand-rolled (no `chrono` / `time`)
//!
//! The crypto-boundary and minimal-dependency posture (LESSONS.md, PRD §5.6)
//! makes every added crate a cost. Formatting a millis-since-epoch value to a
//! civil UTC date needs only integer arithmetic — Howard Hinnant's
//! `civil_from_days` algorithm (public domain, widely used) inverts a day count
//! to `(year, month, day)`. It is exact for the whole proleptic-Gregorian range
//! and is unit-tested against known values, including leap-year boundaries.

/// Milliseconds in a day.
const MS_PER_DAY: i64 = 86_400_000;

/// Format a unix-millis timestamp as `YYYY-MM-DD HH:MMZ` (UTC, minute
/// precision).
///
/// Negative timestamps (before 1970) are handled correctly via floored
/// division, though LocalPass never stores them in practice.
#[must_use]
pub fn format_millis_utc(ms: i64) -> String {
    // Floor-divide into whole days and the millisecond remainder within the day,
    // so pre-epoch values (negative ms) still land on the correct civil day.
    let days = ms.div_euclid(MS_PER_DAY);
    let rem_ms = ms.rem_euclid(MS_PER_DAY);

    let (year, month, day) = civil_from_days(days);

    let secs_of_day = rem_ms / 1000;
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;

    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}Z")
}

/// Convert a count of days since the Unix epoch (1970-01-01) to a civil
/// `(year, month, day)` in the proleptic Gregorian calendar.
///
/// This is Howard Hinnant's `civil_from_days` (public domain), the inverse of
/// `days_from_civil`. `month` is `1..=12` and `day` is `1..=31`.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    // Shift the epoch so the internal "era" arithmetic starts on 0000-03-01.
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // day-of-era      [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day-of-year [0, 365]
    let mp = (5 * doy + 2) / 153; // month shifted so March = 0 [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // day of month [1, 31]
    // Un-shift: March=0..Dec=9 → 3..12, Jan/Feb (10,11) → 1,2 of the next year.
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    // month/day are provably in 1..=12 / 1..=31 here.
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    (year, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_is_1970() {
        assert_eq!(format_millis_utc(0), "1970-01-01 00:00Z");
    }

    #[test]
    fn known_value_from_prd() {
        // The PRD example (Task #9): 2026-07-04 14:03Z. Build the instant from
        // civil parts to avoid a magic constant.
        let days = days_from_civil(2026, 7, 4);
        let target = days * MS_PER_DAY + (14 * 3600 + 3 * 60) * 1000;
        assert_eq!(format_millis_utc(target), "2026-07-04 14:03Z");
    }

    #[test]
    fn leap_day_2024() {
        // 2024 is a leap year: 2024-02-29 exists.
        let days = days_from_civil(2024, 2, 29);
        let ms = days * MS_PER_DAY;
        assert_eq!(format_millis_utc(ms), "2024-02-29 00:00Z");
        // The next day is March 1st.
        assert_eq!(format_millis_utc(ms + MS_PER_DAY), "2024-03-01 00:00Z");
    }

    #[test]
    fn non_leap_century_1900() {
        // 1900 is NOT a leap year (divisible by 100, not 400): Feb 28 → Mar 1.
        let feb28 = days_from_civil(1900, 2, 28) * MS_PER_DAY;
        assert_eq!(format_millis_utc(feb28), "1900-02-28 00:00Z");
        assert_eq!(format_millis_utc(feb28 + MS_PER_DAY), "1900-03-01 00:00Z");
    }

    #[test]
    fn leap_century_2000() {
        // 2000 IS a leap year (divisible by 400): Feb 29 exists.
        let feb29 = days_from_civil(2000, 2, 29) * MS_PER_DAY;
        assert_eq!(format_millis_utc(feb29), "2000-02-29 00:00Z");
    }

    #[test]
    fn time_of_day_truncates_to_minute() {
        // 23:59:59.999 must render 23:59 (seconds/millis dropped, no rollover).
        let ms = (23 * 3600 + 59 * 60 + 59) * 1000 + 999;
        assert_eq!(format_millis_utc(ms), "1970-01-01 23:59Z");
    }

    #[test]
    fn year_end_boundary() {
        // 2023-12-31 23:59Z, then the next minute is 2024-01-01 00:00Z.
        let base = days_from_civil(2023, 12, 31) * MS_PER_DAY + (23 * 3600 + 59 * 60) * 1000;
        assert_eq!(format_millis_utc(base), "2023-12-31 23:59Z");
        assert_eq!(format_millis_utc(base + 60_000), "2024-01-01 00:00Z");
    }

    #[test]
    fn pre_epoch_is_correct() {
        // One day before the epoch is 1969-12-31.
        assert_eq!(format_millis_utc(-MS_PER_DAY), "1969-12-31 00:00Z");
        // One millisecond before the epoch is still on 1969-12-31 (floored day).
        assert_eq!(format_millis_utc(-1), "1969-12-31 23:59Z");
    }

    #[test]
    fn round_trips_many_civil_dates() {
        // civil_from_days is the exact inverse of days_from_civil across a wide
        // range spanning leap rules and both sides of the epoch.
        for (y, m, d) in [
            (1600, 1, 1),
            (1899, 12, 31),
            (1970, 1, 1),
            (2000, 2, 29),
            (2024, 2, 29),
            (2100, 3, 1),
            (2400, 2, 29),
        ] {
            let days = days_from_civil(y, m, d);
            assert_eq!(civil_from_days(days), (y, m, d), "{y}-{m}-{d}");
        }
    }

    /// The forward algorithm (days since epoch from a civil date), used only in
    /// tests to construct known instants. Howard Hinnant's `days_from_civil`.
    fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
        let y = if m <= 2 { y - 1 } else { y };
        let era = if y >= 0 { y } else { y - 399 } / 400;
        let yoe = y - era * 400; // [0, 399]
        let m = i64::from(m);
        let d = i64::from(d);
        let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1; // [0, 365]
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
        era * 146_097 + doe - 719_468
    }
}
