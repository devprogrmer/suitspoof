//! Logging setup using [`simplelog`].
//!
//! Provides:
//! - Coloured terminal output via `TermLogger`
//! - Optional simultaneous file logging via `WriteLogger`
//! - The same startup banner and auto-tune summary helpers as before
//!
//! Output format (terminal):
//!
//!```text
//! 14:23:01 [INFO ] [app] suitspoof client starting ...
//! 
