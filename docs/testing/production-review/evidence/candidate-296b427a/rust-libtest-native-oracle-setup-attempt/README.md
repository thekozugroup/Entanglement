# First run and legacy coordinator setup correction

The [first run](results.json) exercised all nine native-versus-WASI selection cases, all ordinary diagnostic controls, the worker deadline and recovery, and the typed pin rejection. The compatibility checks stopped during startup because this version of the [driver](verify.py) set multi-node mode on the c19 coordinator without granting it any peer. The c19 daemon refused the configuration with `ENTANGLE-E0050`. The [transcript](launch.log) and [daemon log](old-coord.daemon.log) preserve the failure.

The [repeat](../rust-libtest-native-oracle/) grants both daemons permission for an actual configured route. The release archive and the frozen checkout were unchanged.
