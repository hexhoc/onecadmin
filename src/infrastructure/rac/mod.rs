mod arguments;
mod encoding;
mod error;
mod gateway;
mod locator;
mod parser;
mod process;
mod version;

pub use arguments::{RacArgumentBuilder, RacAuthMode, RacCredentials, RacSecret};
pub use encoding::{DecodedRacOutput, RacEncoding, RacOutputDecoder, decode_rac_output};
pub use error::{RacError, RacErrorKind, classify_diagnostic};
pub use gateway::RacGateway;
pub use locator::{
    RacCandidate, RacLocator, RacOrigin, RacVersionSelection, SearchEnvironment, SearchPolicy,
};
pub use parser::{
    RacParseError, RacParseErrorKind, RacRecord, RacRecordParser, normalize_field_name,
    parse_rac_records,
};
pub use process::{
    ProcessIoStage, RacArguments, RacProcessError, RacProcessOutput, RacProcessRunner,
    RedactedInvocation,
};
pub use version::{PlatformVersion, PlatformVersionParseError, RacVersionProbe};
