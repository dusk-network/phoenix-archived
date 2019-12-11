use serde::Deserialize;

pub mod obfuscated;
pub mod transparent;

pub use transparent::TransparentNote;

pub trait PhoenixIdx: for<'de> Deserialize<'de> {}
pub trait PhoenixNote {}

impl PhoenixIdx for () {}
impl PhoenixIdx for u64 {}
