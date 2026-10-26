//! Bounded Myers shortest-edit-script over exact logical-line byte sequences.

use crate::{GkrmError, Result};

/// Primitive line-level edit produced by a side-vs-base Myers SES.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PrimitiveLineEdit {
    Equal {
        base_index: usize,
        side_index: usize,
    },
    DeleteBase {
        base_index: usize,
    },
    InsertSide {
        side_index: usize,
        at_base_index: usize,
    },
}

/// Soft algorithm limit hit while searching for a bounded SES.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SideDiffLimit {
    EditDistance,
    TraceCells,
}

/// Myers diagonal predecessor chosen before extending a snake.
///
/// In classic Myers terms (`a = base`, `b = side`, `k = x - y`):
/// - [`MyersPredecessor::DeleteBase`] arrives from diagonal `k - 1` (horizontal move: `x`
///   advances; base line consumed).
/// - [`MyersPredecessor::InsertSide`] arrives from diagonal `k + 1` (vertical move: `y`
///   advances; side line consumed).
///
/// Classic selection:
/// ```text
/// if k == -d || (k != d && V[k - 1] < V[k + 1]) {
///     x = V[k + 1]; // InsertSide
/// } else {
///     x = V[k - 1] + 1; // DeleteBase
/// }
/// ```
/// When `V[k - 1] == V[k + 1]`, the `else` branch runs → DeleteBase preference.
enum MyersPredecessor {
    DeleteBase { x: usize },
    InsertSide { x: usize },
}

/// Select the shortest Myers predecessor, preferring DeleteBase on equal progress.
///
/// `delete_candidate` is `V[k - 1]` when a delete-from-base move (from diagonal `k - 1`) is
/// admissible; `insert_candidate` is `V[k + 1]` when an insert-side move (from diagonal
/// `k + 1`) is admissible. The returned `x` is the coordinate after applying that move
/// (before the snake).
fn select_shortest_predecessor_preferring_delete_base(
    delete_candidate: Option<usize>,
    insert_candidate: Option<usize>,
) -> Result<MyersPredecessor> {
    match (delete_candidate, insert_candidate) {
        (None, None) => Err(GkrmError::ThreeWayTextDiffArithmeticOverflow),
        (Some(v_del), None) => {
            let x = v_del
                .checked_add(1)
                .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
            Ok(MyersPredecessor::DeleteBase { x })
        }
        (None, Some(v_ins)) => Ok(MyersPredecessor::InsertSide { x: v_ins }),
        (Some(v_del), Some(v_ins)) => {
            // Classic: if V[k-1] < V[k+1] take insert; else take delete.
            // Equality falls through to DeleteBase (explicit preference, not `<` vs `<=` alone).
            if v_del < v_ins {
                Ok(MyersPredecessor::InsertSide { x: v_ins })
            } else {
                let x = v_del
                    .checked_add(1)
                    .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
                Ok(MyersPredecessor::DeleteBase { x })
            }
        }
    }
}

/// Compute a bounded Myers SES comparing exact line bytes.
///
/// Returns `Ok(Ok(script))` on success, `Ok(Err(limit))` when a soft bound is hit, and
/// `Err` for arithmetic overflow.
pub(crate) fn bounded_myers_diff(
    base: &[Vec<u8>],
    side: &[Vec<u8>],
    max_edit_distance: usize,
    max_trace_cells: usize,
) -> Result<std::result::Result<Vec<PrimitiveLineEdit>, SideDiffLimit>> {
    let n = base.len();
    let m = side.len();

    if n == 0 && m == 0 {
        return Ok(Ok(Vec::new()));
    }

    // Need room for diagonals -D..=D plus the classic V[1] sentinel when D == 0.
    let v_len = max_edit_distance
        .checked_mul(2)
        .and_then(|v| v.checked_add(2))
        .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
    let offset = max_edit_distance;

    // V[k] = furthest x on diagonal k after the last completed distance.
    // Classic sentinel: V[1] = 0 so d=0,k=0 reads InsertSide from k+1.
    let mut v = vec![0usize; v_len];
    let sentinel_idx = offset
        .checked_add(1)
        .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
    let slot = v
        .get_mut(sentinel_idx)
        .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
    *slot = 0;

    // Snapshot of V after each distance d (index = d).
    let mut trace: Vec<Vec<usize>> = Vec::new();
    let mut trace_cells: usize = 0;

    for d in 0..=max_edit_distance {
        let d_isize =
            isize::try_from(d).map_err(|_| GkrmError::ThreeWayTextDiffArithmeticOverflow)?;

        for k in (-d_isize..=d_isize).step_by(2) {
            // Classic: `k == -d` forces InsertSide (reads V[k+1]); `k == d` forces
            // DeleteBase (reads V[k-1]). When d == 0 and k == 0 both equalities hold;
            // the `k == -d` branch takes precedence and still reads V[1].
            let force_insert = k == -d_isize;
            let force_delete = k == d_isize && d != 0;

            let delete_candidate = if force_insert {
                None
            } else {
                Some(read_v(&v, offset, k - 1)?)
            };
            let insert_candidate = if force_delete {
                None
            } else {
                Some(read_v(&v, offset, k + 1)?)
            };

            let pred = if force_insert {
                select_shortest_predecessor_preferring_delete_base(None, insert_candidate)?
            } else if force_delete {
                select_shortest_predecessor_preferring_delete_base(delete_candidate, None)?
            } else {
                select_shortest_predecessor_preferring_delete_base(
                    delete_candidate,
                    insert_candidate,
                )?
            };

            let mut x = match pred {
                MyersPredecessor::DeleteBase { x } | MyersPredecessor::InsertSide { x } => x,
            };
            let mut y = checked_y(x, k)?;

            while x < n && y < m && base[x] == side[y] {
                x = x
                    .checked_add(1)
                    .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
                y = y
                    .checked_add(1)
                    .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
            }

            write_v(&mut v, offset, k, x)?;
            trace_cells = trace_cells
                .checked_add(1)
                .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
            if trace_cells > max_trace_cells {
                return Ok(Err(SideDiffLimit::TraceCells));
            }

            if x >= n && y >= m {
                trace.push(v.clone());
                let script = backtrack(base, side, &trace, d, offset)?;
                validate_primitive_script(base, side, &script)?;
                return Ok(Ok(script));
            }
        }

        trace.push(v.clone());
    }

    Ok(Err(SideDiffLimit::EditDistance))
}

fn read_v(v: &[usize], offset: usize, k: isize) -> Result<usize> {
    let idx = v_index(offset, k)?;
    v.get(idx)
        .copied()
        .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)
}

fn write_v(v: &mut [usize], offset: usize, k: isize, x: usize) -> Result<()> {
    let idx = v_index(offset, k)?;
    let slot = v
        .get_mut(idx)
        .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
    *slot = x;
    Ok(())
}

fn v_index(offset: usize, k: isize) -> Result<usize> {
    let offset_i =
        isize::try_from(offset).map_err(|_| GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
    let sum = offset_i
        .checked_add(k)
        .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
    usize::try_from(sum).map_err(|_| GkrmError::ThreeWayTextDiffArithmeticOverflow)
}

fn checked_y(x: usize, k: isize) -> Result<usize> {
    let x_i = isize::try_from(x).map_err(|_| GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
    let y_i = x_i
        .checked_sub(k)
        .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
    usize::try_from(y_i).map_err(|_| GkrmError::ThreeWayTextDiffArithmeticOverflow)
}

fn backtrack(
    base: &[Vec<u8>],
    side: &[Vec<u8>],
    trace: &[Vec<usize>],
    final_d: usize,
    offset: usize,
) -> Result<Vec<PrimitiveLineEdit>> {
    let n = base.len();
    let m = side.len();
    let mut edits: Vec<PrimitiveLineEdit> = Vec::new();
    let mut x = n;
    let mut y = m;

    for d in (1..=final_d).rev() {
        let d_isize =
            isize::try_from(d).map_err(|_| GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
        let prev = trace
            .get(
                d.checked_sub(1)
                    .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?,
            )
            .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;

        let k = isize::try_from(x)
            .map_err(|_| GkrmError::ThreeWayTextDiffArithmeticOverflow)?
            .checked_sub(
                isize::try_from(y).map_err(|_| GkrmError::ThreeWayTextDiffArithmeticOverflow)?,
            )
            .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;

        let force_insert = k == -d_isize;
        let force_delete = k == d_isize && d != 0;

        let delete_candidate = if force_insert {
            None
        } else {
            Some(read_v(prev, offset, k - 1)?)
        };
        let insert_candidate = if force_delete {
            None
        } else {
            Some(read_v(prev, offset, k + 1)?)
        };

        let pred = if force_insert {
            select_shortest_predecessor_preferring_delete_base(None, insert_candidate)?
        } else if force_delete {
            select_shortest_predecessor_preferring_delete_base(delete_candidate, None)?
        } else {
            select_shortest_predecessor_preferring_delete_base(delete_candidate, insert_candidate)?
        };

        // After the edit move (before the snake) we sit on diagonal k at (after_x, after_y).
        let (before_x, before_y, after_x, after_y, edit) = match pred {
            MyersPredecessor::InsertSide { x: px } => {
                // Vertical move from diagonal k+1: (px, before_y) → (px, before_y+1).
                let before_y = checked_y(px, k + 1)?;
                let after_y = before_y
                    .checked_add(1)
                    .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
                (
                    px,
                    before_y,
                    px,
                    after_y,
                    PrimitiveLineEdit::InsertSide {
                        side_index: before_y,
                        at_base_index: px,
                    },
                )
            }
            MyersPredecessor::DeleteBase { x: px } => {
                // Horizontal move from diagonal k-1: (px-1, after_y) → (px, after_y).
                let after_y = checked_y(px, k)?;
                let base_index = px
                    .checked_sub(1)
                    .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
                (
                    base_index,
                    after_y,
                    px,
                    after_y,
                    PrimitiveLineEdit::DeleteBase { base_index },
                )
            }
        };

        // Snake segment between after-move and current (x, y), emitted in reverse.
        let mut sx = x;
        let mut sy = y;
        while sx > after_x && sy > after_y {
            sx = sx
                .checked_sub(1)
                .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
            sy = sy
                .checked_sub(1)
                .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
            edits.push(PrimitiveLineEdit::Equal {
                base_index: sx,
                side_index: sy,
            });
        }

        edits.push(edit);
        x = before_x;
        y = before_y;
    }

    // Remaining snake on d = 0 from (0, 0) to (x, y).
    while x > 0 && y > 0 {
        x = x
            .checked_sub(1)
            .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
        y = y
            .checked_sub(1)
            .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
        edits.push(PrimitiveLineEdit::Equal {
            base_index: x,
            side_index: y,
        });
    }

    edits.reverse();
    Ok(edits)
}

/// Validate that `script` is a monotonic, complete, applying SES from `base` to `side`.
pub(super) fn validate_primitive_script(
    base: &[Vec<u8>],
    side: &[Vec<u8>],
    script: &[PrimitiveLineEdit],
) -> Result<()> {
    let mut next_base = 0usize;
    let mut next_side = 0usize;
    let mut reconstructed: Vec<Vec<u8>> = Vec::new();

    for edit in script {
        match edit {
            PrimitiveLineEdit::Equal {
                base_index,
                side_index,
            } => {
                if *base_index != next_base || *side_index != next_side {
                    return Err(GkrmError::ThreeWayTextDiffInvalidPrimitiveScript);
                }
                let b = base
                    .get(*base_index)
                    .ok_or(GkrmError::ThreeWayTextDiffInvalidPrimitiveScript)?;
                let s = side
                    .get(*side_index)
                    .ok_or(GkrmError::ThreeWayTextDiffInvalidPrimitiveScript)?;
                if b != s {
                    return Err(GkrmError::ThreeWayTextDiffInvalidPrimitiveScript);
                }
                reconstructed.push(b.clone());
                next_base = next_base
                    .checked_add(1)
                    .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
                next_side = next_side
                    .checked_add(1)
                    .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
            }
            PrimitiveLineEdit::DeleteBase { base_index } => {
                if *base_index != next_base {
                    return Err(GkrmError::ThreeWayTextDiffInvalidPrimitiveScript);
                }
                if base.get(*base_index).is_none() {
                    return Err(GkrmError::ThreeWayTextDiffInvalidPrimitiveScript);
                }
                next_base = next_base
                    .checked_add(1)
                    .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
            }
            PrimitiveLineEdit::InsertSide {
                side_index,
                at_base_index,
            } => {
                if *side_index != next_side || *at_base_index != next_base {
                    return Err(GkrmError::ThreeWayTextDiffInvalidPrimitiveScript);
                }
                let s = side
                    .get(*side_index)
                    .ok_or(GkrmError::ThreeWayTextDiffInvalidPrimitiveScript)?;
                reconstructed.push(s.clone());
                next_side = next_side
                    .checked_add(1)
                    .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
            }
        }
    }

    if next_base != base.len() || next_side != side.len() {
        return Err(GkrmError::ThreeWayTextDiffInvalidPrimitiveScript);
    }
    if reconstructed != side {
        return Err(GkrmError::ThreeWayTextDiffInvalidPrimitiveScript);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(xs: &[&str]) -> Vec<Vec<u8>> {
        xs.iter().map(|s| s.as_bytes().to_vec()).collect()
    }

    fn diff(base: &[&str], side: &[&str]) -> Vec<PrimitiveLineEdit> {
        let b = lines(base);
        let s = lines(side);
        let result = bounded_myers_diff(&b, &s, 64, usize::MAX)
            .expect("arith")
            .expect("within limits");
        validate_primitive_script(&b, &s, &result).expect("valid script");
        result
    }

    #[test]
    fn no_changes() {
        assert_eq!(
            diff(&["a", "b"], &["a", "b"]),
            vec![
                PrimitiveLineEdit::Equal {
                    base_index: 0,
                    side_index: 0
                },
                PrimitiveLineEdit::Equal {
                    base_index: 1,
                    side_index: 1
                },
            ]
        );
    }

    #[test]
    fn empty_empty() {
        assert_eq!(diff(&[], &[]), Vec::new());
    }

    #[test]
    fn insert_beginning_middle_end() {
        assert_eq!(
            diff(&["b"], &["a", "b"]),
            vec![
                PrimitiveLineEdit::InsertSide {
                    side_index: 0,
                    at_base_index: 0
                },
                PrimitiveLineEdit::Equal {
                    base_index: 0,
                    side_index: 1
                },
            ]
        );
        assert_eq!(
            diff(&["a", "c"], &["a", "b", "c"]),
            vec![
                PrimitiveLineEdit::Equal {
                    base_index: 0,
                    side_index: 0
                },
                PrimitiveLineEdit::InsertSide {
                    side_index: 1,
                    at_base_index: 1
                },
                PrimitiveLineEdit::Equal {
                    base_index: 1,
                    side_index: 2
                },
            ]
        );
        assert_eq!(
            diff(&["a"], &["a", "b"]),
            vec![
                PrimitiveLineEdit::Equal {
                    base_index: 0,
                    side_index: 0
                },
                PrimitiveLineEdit::InsertSide {
                    side_index: 1,
                    at_base_index: 1
                },
            ]
        );
    }

    #[test]
    fn delete_beginning_middle_end() {
        assert_eq!(
            diff(&["a", "b"], &["b"]),
            vec![
                PrimitiveLineEdit::DeleteBase { base_index: 0 },
                PrimitiveLineEdit::Equal {
                    base_index: 1,
                    side_index: 0
                },
            ]
        );
        assert_eq!(
            diff(&["a", "b", "c"], &["a", "c"]),
            vec![
                PrimitiveLineEdit::Equal {
                    base_index: 0,
                    side_index: 0
                },
                PrimitiveLineEdit::DeleteBase { base_index: 1 },
                PrimitiveLineEdit::Equal {
                    base_index: 2,
                    side_index: 1
                },
            ]
        );
        assert_eq!(
            diff(&["a", "b"], &["a"]),
            vec![
                PrimitiveLineEdit::Equal {
                    base_index: 0,
                    side_index: 0
                },
                PrimitiveLineEdit::DeleteBase { base_index: 1 },
            ]
        );
    }

    #[test]
    fn replacement() {
        assert_eq!(
            diff(&["a", "b", "c"], &["a", "x", "c"]),
            vec![
                PrimitiveLineEdit::Equal {
                    base_index: 0,
                    side_index: 0
                },
                PrimitiveLineEdit::DeleteBase { base_index: 1 },
                PrimitiveLineEdit::InsertSide {
                    side_index: 1,
                    at_base_index: 2
                },
                PrimitiveLineEdit::Equal {
                    base_index: 2,
                    side_index: 2
                },
            ]
        );
    }

    #[test]
    fn multiple_separated_edits() {
        assert_eq!(
            diff(&["a", "b", "c", "d"], &["a", "x", "c", "y"]),
            vec![
                PrimitiveLineEdit::Equal {
                    base_index: 0,
                    side_index: 0
                },
                PrimitiveLineEdit::DeleteBase { base_index: 1 },
                PrimitiveLineEdit::InsertSide {
                    side_index: 1,
                    at_base_index: 2
                },
                PrimitiveLineEdit::Equal {
                    base_index: 2,
                    side_index: 2
                },
                PrimitiveLineEdit::DeleteBase { base_index: 3 },
                PrimitiveLineEdit::InsertSide {
                    side_index: 3,
                    at_base_index: 4
                },
            ]
        );
    }

    #[test]
    fn repeated_equal_lines_ambiguous_matching() {
        // base ["x","x","y"] vs side ["x","y","x"]: SES prefers delete-first geometry.
        assert_eq!(
            diff(&["x", "x", "y"], &["x", "y", "x"]),
            vec![
                PrimitiveLineEdit::Equal {
                    base_index: 0,
                    side_index: 0
                },
                PrimitiveLineEdit::DeleteBase { base_index: 1 },
                PrimitiveLineEdit::Equal {
                    base_index: 2,
                    side_index: 1
                },
                PrimitiveLineEdit::InsertSide {
                    side_index: 2,
                    at_base_index: 3
                },
            ]
        );
    }

    #[test]
    fn ambiguous_ses_prefers_delete_base() {
        // Two SES of length 2 exist for base=["A","B"] side=["B","A"]:
        //   1) Delete A, Equal B, Insert A   ← classic Myers (DeleteBase preference)
        //   2) Insert B, Equal A, Delete B   ← would be chosen if the V[k-1] < V[k+1]
        //      insert sense were reversed; this test would then fail.
        assert_eq!(
            diff(&["A", "B"], &["B", "A"]),
            vec![
                PrimitiveLineEdit::DeleteBase { base_index: 0 },
                PrimitiveLineEdit::Equal {
                    base_index: 1,
                    side_index: 0
                },
                PrimitiveLineEdit::InsertSide {
                    side_index: 1,
                    at_base_index: 2
                },
            ]
        );
    }

    #[test]
    fn empty_base_all_inserts() {
        assert_eq!(
            diff(&[], &["a", "b"]),
            vec![
                PrimitiveLineEdit::InsertSide {
                    side_index: 0,
                    at_base_index: 0
                },
                PrimitiveLineEdit::InsertSide {
                    side_index: 1,
                    at_base_index: 0
                },
            ]
        );
    }

    #[test]
    fn empty_side_all_deletes() {
        assert_eq!(
            diff(&["a", "b"], &[]),
            vec![
                PrimitiveLineEdit::DeleteBase { base_index: 0 },
                PrimitiveLineEdit::DeleteBase { base_index: 1 },
            ]
        );
    }

    #[test]
    fn edit_distance_limit() {
        let base = lines(&["a"]);
        let side = lines(&["b"]);
        let limited = bounded_myers_diff(&base, &side, 0, usize::MAX)
            .expect("arith")
            .expect_err("limit");
        assert_eq!(limited, SideDiffLimit::EditDistance);
    }

    #[test]
    fn trace_cells_limit() {
        let base = lines(&["a", "b", "c"]);
        let side = lines(&["x", "y", "z"]);
        let limited = bounded_myers_diff(&base, &side, 64, 1)
            .expect("arith")
            .expect_err("trace");
        assert_eq!(limited, SideDiffLimit::TraceCells);
    }

    #[test]
    fn predecessor_helper_prefers_delete_on_equal_v() {
        match select_shortest_predecessor_preferring_delete_base(Some(3), Some(3)).expect("pred") {
            MyersPredecessor::DeleteBase { x } => assert_eq!(x, 4),
            MyersPredecessor::InsertSide { .. } => panic!("expected delete preference on tie"),
        }
        match select_shortest_predecessor_preferring_delete_base(Some(2), Some(5)).expect("pred") {
            MyersPredecessor::InsertSide { x } => assert_eq!(x, 5),
            MyersPredecessor::DeleteBase { .. } => panic!("expected insert when V[k-1] < V[k+1]"),
        }
    }

    #[test]
    fn malformed_scripts_use_task17_error_variant() {
        let base = lines(&["a", "b"]);
        let side = lines(&["a", "b"]);

        let cases: Vec<(&str, Vec<PrimitiveLineEdit>)> = vec![
            (
                "non-monotonic indexes",
                vec![PrimitiveLineEdit::Equal {
                    base_index: 1,
                    side_index: 0,
                }],
            ),
            (
                "duplicate base consumption",
                vec![
                    PrimitiveLineEdit::DeleteBase { base_index: 0 },
                    PrimitiveLineEdit::Equal {
                        base_index: 0,
                        side_index: 0,
                    },
                ],
            ),
            (
                "duplicate side consumption",
                vec![
                    PrimitiveLineEdit::InsertSide {
                        side_index: 0,
                        at_base_index: 0,
                    },
                    PrimitiveLineEdit::Equal {
                        base_index: 0,
                        side_index: 0,
                    },
                ],
            ),
            (
                "missing base coverage",
                vec![PrimitiveLineEdit::Equal {
                    base_index: 0,
                    side_index: 0,
                }],
            ),
            (
                "missing side coverage",
                vec![
                    PrimitiveLineEdit::Equal {
                        base_index: 0,
                        side_index: 0,
                    },
                    PrimitiveLineEdit::DeleteBase { base_index: 1 },
                ],
            ),
            (
                "out-of-range base index",
                vec![PrimitiveLineEdit::DeleteBase { base_index: 9 }],
            ),
            (
                "out-of-range side index",
                vec![PrimitiveLineEdit::InsertSide {
                    side_index: 9,
                    at_base_index: 0,
                }],
            ),
            (
                "invalid insertion anchor",
                vec![PrimitiveLineEdit::InsertSide {
                    side_index: 0,
                    at_base_index: 1,
                }],
            ),
            (
                "malformed terminal cursor state",
                vec![
                    PrimitiveLineEdit::Equal {
                        base_index: 0,
                        side_index: 0,
                    },
                    PrimitiveLineEdit::Equal {
                        base_index: 1,
                        side_index: 1,
                    },
                    PrimitiveLineEdit::InsertSide {
                        side_index: 2,
                        at_base_index: 2,
                    },
                ],
            ),
        ];

        let mismatch_base = lines(&["a", "b"]);
        let mismatch_side = lines(&["a", "c"]);
        let err = validate_primitive_script(
            &mismatch_base,
            &mismatch_side,
            &[
                PrimitiveLineEdit::Equal {
                    base_index: 0,
                    side_index: 0,
                },
                PrimitiveLineEdit::Equal {
                    base_index: 1,
                    side_index: 1,
                },
            ],
        )
        .expect_err("reconstruction mismatch");
        assert!(matches!(
            err,
            GkrmError::ThreeWayTextDiffInvalidPrimitiveScript
        ));
        assert!(!matches!(err, GkrmError::ThreeWayInternalInvariant));

        for (label, script) in cases {
            let err = validate_primitive_script(&base, &side, &script).expect_err(label);
            assert!(
                matches!(err, GkrmError::ThreeWayTextDiffInvalidPrimitiveScript),
                "{label}: {err:?}"
            );
            assert!(!matches!(err, GkrmError::ThreeWayInternalInvariant));
            let display = format!("{err}");
            assert!(!display.contains("a\nb"), "{label} leaked content");
            assert!(!display.contains("side_index"), "{label} leaked indexes");
        }

        // Production Myers output still reconstructs.
        let _ = diff(&["a", "b", "c"], &["a", "x", "c"]);
    }
}
