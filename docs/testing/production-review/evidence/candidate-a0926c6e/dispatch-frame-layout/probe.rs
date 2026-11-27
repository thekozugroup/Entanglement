use std::{mem::{align_of, size_of}, sync::Arc};
use entangle_bin::{methods, state::DaemonState};
use entangle_scheduler::Dispatcher;
use entangle_types::task::OneShotTask;

fn two<A,B,R>(_:impl FnOnce(A,B)->R) -> [usize; 2] {
    [size_of::<R>(), align_of::<R>()]
}
#[cfg(candidate)]
fn three<A,B,C,R>(_:impl FnOnce(A,B,C)->R) -> [usize; 2] {
    [size_of::<R>(), align_of::<R>()]
}

#[no_mangle]
pub fn rpc_layout() -> [usize; 2] {
    two::<&'static str,&'static Arc<DaemonState>,_>(methods::dispatch)
}
#[no_mangle]
pub fn public_one_shot() -> [usize; 2] {
    two::<&'static Dispatcher,OneShotTask,_>(Dispatcher::dispatch_one_shot)
}
#[cfg(candidate)]
#[no_mangle]
pub fn actual_one_shot() -> [usize; 2] {
    three::<&'static Dispatcher,OneShotTask,Option<&'static dyn entangle_scheduler::PlacementRefresh>,_>(
        Dispatcher::dispatch_one_shot_with_refresh)
}
