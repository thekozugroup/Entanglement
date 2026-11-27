; ModuleID = 'frame_probe.237c13bf070702a2-cgu.0'
source_filename = "frame_probe.237c13bf070702a2-cgu.0"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

; Function Attrs: mustprogress nofree norecurse nosync nounwind nonlazybind willreturn memory(argmem: write) uwtable
define void @actual_one_shot(ptr dead_on_unwind noalias noundef writable writeonly sret([16 x i8]) align 8 captures(none) dereferenceable(16) initializes((0, 16)) %_0) unnamed_addr #0 {
start:
  store i64 2720, ptr %_0, align 8
  %0 = getelementptr inbounds nuw i8, ptr %_0, i64 8
  store i64 16, ptr %0, align 8
  ret void
}

; Function Attrs: mustprogress nofree norecurse nosync nounwind nonlazybind willreturn memory(argmem: write) uwtable
define void @public_one_shot(ptr dead_on_unwind noalias noundef writable writeonly sret([16 x i8]) align 8 captures(none) dereferenceable(16) initializes((0, 16)) %_0) unnamed_addr #0 {
start:
  store i64 2992, ptr %_0, align 8
  %0 = getelementptr inbounds nuw i8, ptr %_0, i64 8
  store i64 16, ptr %0, align 8
  ret void
}

; Function Attrs: mustprogress nofree norecurse nosync nounwind nonlazybind willreturn memory(argmem: write) uwtable
define void @rpc_layout(ptr dead_on_unwind noalias noundef writable writeonly sret([16 x i8]) align 8 captures(none) dereferenceable(16) initializes((0, 16)) %_0) unnamed_addr #0 {
start:
  store i64 3744, ptr %_0, align 8
  %0 = getelementptr inbounds nuw i8, ptr %_0, i64 8
  store i64 16, ptr %0, align 8
  ret void
}

attributes #0 = { mustprogress nofree norecurse nosync nounwind nonlazybind willreturn memory(argmem: write) uwtable "probe-stack"="inline-asm" "target-cpu"="x86-64" }

!llvm.module.flags = !{!0, !1}
!llvm.ident = !{!2}

!0 = !{i32 8, !"PIC Level", i32 2}
!1 = !{i32 2, !"RtLibUseGOT", i32 1}
!2 = !{!"rustc version 1.91.1 (ed61e7d7e 2025-11-07)"}
