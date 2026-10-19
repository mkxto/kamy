use std::collections::HashMap;

use kamy_core::Function;

/// Dominator tree over a function's basic blocks, indexed by block position in
/// `Function::blocks`.
///
/// Built with the Cooper–Harvey–Kennedy iterative algorithm. Unreachable blocks
/// have no immediate dominator.
pub struct DomTree {
    idom: Vec<Option<usize>>,
}

impl DomTree {
    /// Immediate dominator of `block`, or `None` for the entry and unreachable
    /// blocks.
    pub fn immediate_dominator(&self, block: usize) -> Option<usize> {
        self.idom[block]
    }

    /// Whether `a` dominates `b` (reflexive: a block dominates itself).
    pub fn dominates(&self, a: usize, b: usize) -> bool {
        if a == b {
            return true;
        }
        let mut cur = b;
        while let Some(parent) = self.idom[cur] {
            if parent == a {
                return true;
            }
            cur = parent;
        }
        false
    }
}

struct Graph {
    succs: Vec<Vec<usize>>,
    preds: Vec<Vec<usize>>,
    entry: usize,
}

fn build_graph(func: &Function) -> Graph {
    let index_of: HashMap<u32, usize> = func
        .blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.start.get(), i))
        .collect();

    let succs: Vec<Vec<usize>> = func
        .blocks
        .iter()
        .map(|b| {
            b.successors
                .iter()
                .filter_map(|s| index_of.get(&s.get()).copied())
                .collect()
        })
        .collect();

    let mut preds = vec![Vec::new(); func.blocks.len()];
    for (b, outs) in succs.iter().enumerate() {
        for &s in outs {
            preds[s].push(b);
        }
    }

    let entry = index_of.get(&func.entry.get()).copied().unwrap_or(0);
    Graph {
        succs,
        preds,
        entry,
    }
}

pub fn dominator_tree(func: &Function) -> DomTree {
    let n = func.blocks.len();
    if n == 0 {
        return DomTree { idom: Vec::new() };
    }
    let graph = build_graph(func);
    let entry = graph.entry;

    let mut postorder = vec![usize::MAX; n];
    let mut visited = vec![false; n];
    let mut order = Vec::new();
    let mut stack = vec![(entry, 0usize)];
    visited[entry] = true;
    while let Some(&(node, cursor)) = stack.last() {
        if cursor < graph.succs[node].len() {
            stack.last_mut().unwrap().1 += 1;
            let next = graph.succs[node][cursor];
            if !visited[next] {
                visited[next] = true;
                stack.push((next, 0));
            }
        } else {
            postorder[node] = order.len();
            order.push(node);
            stack.pop();
        }
    }
    let rpo: Vec<usize> = order.iter().rev().copied().collect();

    let mut idom = vec![None::<usize>; n];
    idom[entry] = Some(entry);
    let mut changed = true;
    while changed {
        changed = false;
        for &b in &rpo {
            if b == entry {
                continue;
            }
            let mut new_idom: Option<usize> = None;
            for &p in &graph.preds[b] {
                if idom[p].is_none() {
                    continue;
                }
                new_idom = Some(match new_idom {
                    None => p,
                    Some(cur) => intersect(p, cur, &idom, &postorder),
                });
            }
            if new_idom != idom[b] {
                idom[b] = new_idom;
                changed = true;
            }
        }
    }
    idom[entry] = None;

    tracing::debug!(nodes = n, "computed dominator tree");
    DomTree { idom }
}

fn intersect(mut a: usize, mut b: usize, idom: &[Option<usize>], postorder: &[usize]) -> usize {
    while a != b {
        while postorder[a] < postorder[b] {
            a = idom[a].unwrap();
        }
        while postorder[b] < postorder[a] {
            b = idom[b].unwrap();
        }
    }
    a
}

/// Dominance frontier of every block (grilling D7: the φ-node placement set).
pub fn dominance_frontiers(func: &Function, dom: &DomTree) -> Vec<Vec<usize>> {
    let n = func.blocks.len();
    let graph = build_graph(func);
    let mut df = vec![Vec::new(); n];

    for b in 0..n {
        if graph.preds[b].len() < 2 {
            continue;
        }
        let idom_b = dom.idom[b];
        for &p in &graph.preds[b] {
            if dom.idom[p].is_none() && p != b {
                continue;
            }
            let mut runner = p;
            while Some(runner) != idom_b {
                if !df[runner].contains(&b) {
                    df[runner].push(b);
                }
                match dom.idom[runner] {
                    Some(parent) => runner = parent,
                    None => break,
                }
            }
        }
    }
    df
}

#[cfg(test)]
mod tests {
    use super::*;
    use kamy_core::{BasicBlock, Function, Rva, Terminator};

    fn block(start: u32, succ: &[u32]) -> BasicBlock {
        BasicBlock {
            start: Rva::new(start),
            end: Rva::new(start + 1),
            successors: succ.iter().map(|&s| Rva::new(s)).collect(),
            terminator: Terminator::Return,
        }
    }

    // A -> B, A -> C, B -> D, C -> D
    fn diamond() -> Function {
        Function {
            entry: Rva::new(0),
            blocks: vec![
                block(0, &[1, 2]),
                block(1, &[3]),
                block(2, &[3]),
                block(3, &[]),
            ],
        }
    }

    #[test]
    fn diamond_idoms() {
        let f = diamond();
        let dom = dominator_tree(&f);
        assert_eq!(dom.immediate_dominator(0), None);
        assert_eq!(dom.immediate_dominator(1), Some(0));
        assert_eq!(dom.immediate_dominator(2), Some(0));
        assert_eq!(dom.immediate_dominator(3), Some(0));
        assert!(dom.dominates(0, 3));
        assert!(!dom.dominates(1, 3));
    }

    #[test]
    fn diamond_frontiers() {
        let f = diamond();
        let dom = dominator_tree(&f);
        let df = dominance_frontiers(&f, &dom);
        assert_eq!(df[1], vec![3]);
        assert_eq!(df[2], vec![3]);
        assert!(df[0].is_empty());
        assert!(df[3].is_empty());
    }

    #[test]
    fn self_loop_header_in_own_frontier() {
        // A -> B, B -> B, B -> C
        let f = Function {
            entry: Rva::new(0),
            blocks: vec![block(0, &[1]), block(1, &[1, 2]), block(2, &[])],
        };
        let dom = dominator_tree(&f);
        assert_eq!(dom.immediate_dominator(1), Some(0));
        assert_eq!(dom.immediate_dominator(2), Some(1));
        let df = dominance_frontiers(&f, &dom);
        assert_eq!(df[1], vec![1]);
    }
}
