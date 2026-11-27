;; Import-free ABI fixture. Distance is 0 for equal byte strings, otherwise 1.
(component
  (core module $m
    (memory (export "memory") 2)
    (global $next (mut i32) (i32.const 16))
    (func (export "realloc") (param i32 i32 i32) (param $size i32) (result i32)
      (local $ptr i32)
      (local.set $ptr (global.get $next))
      (global.set $next (i32.add (local.get $ptr) (local.get $size)))
      (local.get $ptr))
    (func (export "compare") (param $a i32) (param $na i32) (param $b i32) (param $nb i32) (result f64)
      (local $i i32)
      (if (i32.ne (local.get $na) (local.get $nb)) (then (return (f64.const 1))))
      (block $equal
        (loop $nextbyte
          (br_if $equal (i32.ge_u (local.get $i) (local.get $na)))
          (if (i32.ne (i32.load8_u (i32.add (local.get $a) (local.get $i)))
                      (i32.load8_u (i32.add (local.get $b) (local.get $i))))
            (then (return (f64.const 1))))
          (local.set $i (i32.add (local.get $i) (i32.const 1)))
          (br $nextbyte)))
      (f64.const 0)))
  (core instance $i (instantiate $m))
  (func $compare (param "a" (list u8)) (param "b" (list u8)) (result f64)
    (canon lift (core func $i "compare") (memory $i "memory") (realloc (func $i "realloc"))))
  (instance $metric (export "compare" (func $compare)))
  (export "entangle:integrity/metric@0.1.0" (instance $metric)))
