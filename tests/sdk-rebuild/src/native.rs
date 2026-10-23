// Shared by the SDK's mapped-image probes and codegen's registered-buffer
// regression, so both use the same independent machine/sentinel semantics.
include!("native_probe.rs");

#[cfg(windows)]
pub unsafe fn check_ranges(image: *const u8, image_size: u32, ranges: &str) -> Result<()> {
    let mut generated = 0;
    let mut authored = 0;
    let mut host = 0;
    let mut total = 0;
    let mut epilogues = 0;
    let mut body_pcs = 0;
    let mut successive_call_functions = 0;
    let mut max_frame = 0;
    let mut saved_gpr = 0u16;
    let mut saved_xmm = 0u16;
    for range in ranges.split(',').filter(|value| !value.is_empty()) {
        let (origin, coordinates) = range
            .split_once('@')
            .context("unwind probe MUST be origin@function-start:probe-pc:function-end")?;
        match origin {
            "generated" => generated += 1,
            "authored" => authored += 1,
            "host" => host += 1,
            _ => bail!("invalid unwind origin {origin}"),
        }
        let mut coordinates = coordinates.split(':');
        let begin: u32 = coordinates
            .next()
            .context("unwind probe lacks logical start")?
            .parse()?;
        let pc: u32 = coordinates
            .next()
            .context("unwind probe lacks exact PC")?
            .parse()?;
        let end: u32 = coordinates
            .next()
            .context("unwind probe lacks logical end")?
            .parse()?;
        ensure!(
            coordinates.next().is_none(),
            "unwind probe has extra coordinates"
        );
        ensure!(
            begin <= pc && pc < end && end <= image_size,
            "unwind probe coordinates lie outside mapped image/function"
        );
        let report = unsafe { windows_oracle::check_function(image, begin, end)? };
        ensure!(
            report.anchor == pc,
            "unwind anchor is not independently decoded"
        );
        successive_call_functions += usize::from(report.calls >= 2);
        total += report.pcs;
        epilogues += report.epilogues;
        body_pcs += report.body_pcs;
        max_frame = max_frame.max(report.max_frame);
        saved_gpr |= report.saved_gpr;
        saved_xmm |= report.saved_xmm;
    }
    ensure!(
        (generated > 0 && authored > 0) || host > 0,
        "native unwind MUST exercise generated/authored code or the standalone frame host"
    );
    ensure!(epilogues > 0, "native unwind did not reach an epilogue");
    if host > 0 {
        ensure!(
            max_frame > 4096 && saved_gpr != 0 && saved_xmm != 0,
            "frame oracle did not exercise large allocation and both GPR/XMM saves"
        );
        ensure!(
            successive_call_functions != 0,
            "frame oracle did not unwind a real body containing successive calls"
        );
    }
    println!(
        "unwind_generated={generated} unwind_authored={authored} unwind_host={host} unwind_pcs={total} unwind_body_pcs={body_pcs} unwind_epilogues={epilogues} unwind_successive_call_functions={successive_call_functions} max_frame={max_frame} saved_gpr={} saved_xmm={}",
        saved_gpr.count_ones(),
        saved_xmm.count_ones()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inherited_frame_uses_logical_origin_after_endbr_and_nop() {
        let code = [
            0xf3, 0x0f, 0x1e, 0xfa, 0x90, 0x48, 0x83, 0xec, 0x48, 0x85, 0xc0, 0xc3,
        ];
        let prologue = decode_prologue(&code, 0x1000).unwrap();
        assert_eq!(prologue.pc, 0x1009);
        let snapshots = machine_snapshots(&code, 0x1000).unwrap();
        let machine = &snapshots
            .iter()
            .find(|snapshot| snapshot.pc == prologue.pc)
            .unwrap()
            .machine;
        assert_eq!(machine.rsp().unwrap(), -72);
        assert_eq!(machine.stack[&0].value, Value::Bits(RETURN_PC.into()));
        assert_eq!(
            machine_snapshots(&code[9..], 0x1009).unwrap()[0]
                .machine
                .rsp()
                .unwrap(),
            0
        );
    }

    #[test]
    fn prologue_records_actual_gpr_xmm_and_frame_pointer_values() {
        let code = [
            0x53, 0x55, 0x48, 0x83, 0xec, 0x28, 0x48, 0x8b, 0xec, 0x0f, 0x29, 0x34, 0x24, 0x48,
            0x31, 0xdb, 0xc3,
        ];
        let prologue = decode_prologue(&code, 0x2000).unwrap();
        assert_eq!(prologue.pc, 0x200d);
        let snapshots = machine_snapshots(&code, 0x2000).unwrap();
        let machine = &snapshots
            .iter()
            .find(|snapshot| snapshot.pc == prologue.pc)
            .unwrap()
            .machine;
        assert_eq!(machine.rsp().unwrap(), -56);
        assert_eq!(
            machine.stack[&-8].value,
            Value::Bits(gpr_sentinel(3).into())
        );
        assert_eq!(
            machine.stack[&-16].value,
            Value::Bits(gpr_sentinel(5).into())
        );
        assert_eq!(machine.stack[&-56].value, Value::Bits(xmm_sentinel(6)));
        assert_eq!(machine.registers[5], Value::Stack(-56));
        assert_eq!(machine.saved_gpr, (1 << 3) | (1 << 5));
        assert_eq!(machine.saved_xmm, 1 << 6);
    }

    #[test]
    fn body_and_epilogue_restore_independent_large_frame_sentinels() {
        let code = [
            0x48, 0x81, 0xec, 0x00, 0x30, 0x00, 0x00, 0x85, 0x04, 0x24, 0x48, 0x89, 0x5c, 0x24,
            0x10, 0x0f, 0x11, 0x74, 0x24, 0x20, 0x31, 0xdb, 0x0f, 0x57, 0xf6, 0x0f, 0x10, 0x74,
            0x24, 0x20, 0x48, 0x8b, 0x5c, 0x24, 0x10, 0x48, 0x81, 0xc4, 0x00, 0x30, 0x00, 0x00,
            0xc3,
        ];
        let snapshots = machine_snapshots(&code, 0x3000).unwrap();
        assert!(
            snapshots
                .iter()
                .any(|snapshot| snapshot.machine.rsp().unwrap() == -0x3000)
        );
        assert!(
            snapshots
                .iter()
                .any(|snapshot| snapshot.machine.registers[3] == Value::Unknown)
        );
        assert!(
            snapshots
                .iter()
                .any(|snapshot| snapshot.machine.vectors[6] == Value::Bits(0))
        );
        let returned = snapshots.last().unwrap();
        assert!(returned.epilogue);
        assert_eq!(returned.machine.rsp().unwrap(), 0);
        assert_eq!(
            returned.machine.registers[3],
            Value::Bits(gpr_sentinel(3).into())
        );
        assert_eq!(returned.machine.vectors[6], Value::Bits(xmm_sentinel(6)));
    }

    #[test]
    fn cfg_join_keeps_stack_state_without_ambient_scalar_values() {
        let code = [
            0x53, 0x48, 0x83, 0xec, 0x20, 0x85, 0xc9, 0x74, 0x05, 0xb8, 0x01, 0x00, 0x00, 0x00,
            0x31, 0xdb, 0x48, 0x83, 0xc4, 0x20, 0x5b, 0xc3,
        ];
        let snapshots = machine_snapshots(&code, 0x4000).unwrap();
        let returned = snapshots.last().unwrap();
        assert_eq!(returned.machine.rsp().unwrap(), 0);
        assert_eq!(
            returned.machine.registers[3],
            Value::Bits(gpr_sentinel(3).into())
        );
    }

    #[test]
    fn bl_and_register_movss_preserve_the_other_nonvolatile_bits() {
        let code = [
            0xb3, 0x5a, // mov bl,0x5a
            0x0f, 0x57, 0xc0, // xorps xmm0,xmm0
            0xf3, 0x0f, 0x10, 0xf0, // movss xmm6,xmm0 (register form)
            0xc3,
        ];
        let snapshots = machine_snapshots(&code, 0x6000).unwrap();
        let after_bl = &snapshots
            .iter()
            .find(|snapshot| snapshot.pc == 0x6002)
            .unwrap()
            .machine;
        let scalar = (gpr_sentinel(3) & !0xff) | 0x5a;
        assert_eq!(after_bl.registers[3], Value::Bits(u128::from(scalar)));
        assert_eq!(after_bl.vectors[6], Value::Bits(xmm_sentinel(6)));
        let after_movss = &snapshots.last().unwrap().machine;
        assert_eq!(after_movss.registers[3], Value::Bits(u128::from(scalar)));
        assert_eq!(
            after_movss.vectors[6],
            Value::Bits(xmm_sentinel(6) & !u128::from(u32::MAX))
        );
        assert_ne!(
            xmm_sentinel(6) >> 32,
            0,
            "upper 96 bits MUST exercise preservation"
        );
    }

    #[test]
    fn unsupported_prologue_construction_fails_specifically() {
        let dynamic = [0x48, 0x29, 0xc4, 0xc3];
        assert!(
            format!("{:#}", decode_prologue(&dynamic, 0).unwrap_err())
                .contains("dynamic prologue stack arithmetic")
        );
        let enter = [0xc8, 0x20, 0x00, 0x00, 0xc3];
        assert!(
            format!("{:#}", decode_prologue(&enter, 0).unwrap_err())
                .contains("cannot simulate prologue stack instruction")
        );
    }
}
