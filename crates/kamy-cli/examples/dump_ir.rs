use kamy_core::ir::*;
use kamy_disasm::discover_functions;
use kamy_lift::lift_function;
use kamy_pe::PeFile;

fn main() {
    let path = std::env::args().nth(1).expect("usage: dump_ir <pe>");
    let bytes = std::fs::read(&path).unwrap();
    let pe = PeFile::parse(&bytes).unwrap();
    let mut module = pe.to_module();
    let seeds = pe.seeds();
    module.functions = discover_functions(&module, &seeds);

    let cc = Win64Default;

    for func in &module.functions {
        let blocks = func.blocks.len();
        if blocks < 2 || blocks > 6 { continue; }
        let mut result = lift_function(&module, func, &cc);
        let entry_va = module.image_base + func.entry.get() as u64;
        let has_self_call = result.func.blocks.iter().any(|b| {
            b.insts.iter().any(|i| match &i.op {
                IrOp::Call { target } => *target == entry_va,
                _ => false,
            })
        });
        if !has_self_call { continue; }

        kamy_lift::ssa::construct_ssa(&mut result);
        kamy_transforms::optimize(&mut result.func);

        println!("=== fib at {} — post-SSA, post-optimizer ({} blocks) ===\n",
            func.entry, result.func.blocks.len());
        dump(&result.func);
        return;
    }
    eprintln!("no fib-like recursive function found");
}

fn dump(f: &IrFunction) {
    println!("entry: {:?}  values: {}\n", f.entry, f.next_value);
    for block in &f.blocks {
        println!("block {:?}:", block.id);
        for phi in &block.phis {
            let args: Vec<String> = phi.args.iter()
                .map(|(b, v)| format!("b{}:v{}", b.0, v.0)).collect();
            println!("  v{} = phi {:?} [{}]", phi.dest.0, phi.ty, args.join(", "));
        }
        for inst in &block.insts {
            let d = inst.dest.map_or("void".into(), |d| format!("v{}", d.0));
            let args: Vec<String> = inst.args.iter().map(|v| format!("v{}", v.0)).collect();
            let op = match &inst.op {
                IrOp::Const(v) => {
                    if *v > 0xffff { format!("Const(0x{:x})", v) }
                    else { format!("Const({})", v) }
                }
                IrOp::Call { target } => format!("Call(0x{:x})", target),
                IrOp::NativeInline(n) => format!("NativeInline({} bytes)", n.bytes.len()),
                other => format!("{:?}", other),
            };
            println!("  {} = {} ({}) : {:?}", d, op, args.join(", "), inst.ty);
        }
        let term = match &block.term {
            IrTerminator::Ret => "ret".into(),
            IrTerminator::Jump(b) => format!("jump b{}", b.0),
            IrTerminator::Branch { cond, taken, not_taken } =>
                format!("branch v{} ? b{} : b{}", cond.0, taken.0, not_taken.0),
            IrTerminator::Unreachable => "unreachable".into(),
        };
        println!("  => {}\n", term);
    }
}
