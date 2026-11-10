pub use ut_core::i18n::*;

#[macro_export]
macro_rules! t {
    ($key:expr) => {
        $crate::i18n::translate($key)
    };
    ($key:expr, $($name:ident = $value:expr),+) => {
        $crate::i18n::translate_with_args($key, &[
            $((stringify!($name), $value.to_string())),+
        ])
    };
}

