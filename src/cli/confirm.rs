use std::io::{self, BufRead, IsTerminal, Write};

/// Explicit result of a destructive-operation confirmation request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Confirmation {
    Confirmed,
    Declined,
    NonInteractive,
}

/// Requests confirmation from the controlling terminal.
///
/// Both the preview and prompt are written to stderr. Redirected stdin or
/// stderr is treated as non-interactive instead of implicitly confirming.
pub fn confirm(prompt: &str, preview: &str) -> io::Result<Confirmation> {
    let stdin = io::stdin();
    let stderr = io::stderr();
    let interactive = stdin.is_terminal() && stderr.is_terminal();
    let mut input = stdin.lock();
    let mut output = stderr.lock();
    confirm_with_io(&mut input, &mut output, interactive, prompt, preview)
}

/// Testable confirmation core. `output` represents stderr, never stdout.
pub fn confirm_with_io<R, W>(
    input: &mut R,
    output: &mut W,
    interactive: bool,
    prompt: &str,
    preview: &str,
) -> io::Result<Confirmation>
where
    R: BufRead,
    W: Write,
{
    if !preview.is_empty() {
        output.write_all(preview.as_bytes())?;
        if !preview.ends_with('\n') {
            output.write_all(b"\n")?;
        }
    }

    if !interactive {
        output.flush()?;
        return Ok(Confirmation::NonInteractive);
    }

    write!(output, "{prompt} [y/N]: ")?;
    output.flush()?;

    let mut answer = String::new();
    if input.read_line(&mut answer)? == 0 {
        return Ok(Confirmation::Declined);
    }
    let answer = answer.trim();
    if answer.eq_ignore_ascii_case("y")
        || answer.eq_ignore_ascii_case("yes")
        || answer.eq_ignore_ascii_case("д")
        || answer.eq_ignore_ascii_case("да")
    {
        Ok(Confirmation::Confirmed)
    } else {
        Ok(Confirmation::Declined)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn confirmation_writes_preview_and_prompt_only_to_supplied_stderr() {
        let mut input = Cursor::new("да\n".as_bytes());
        let mut stderr = Vec::new();

        let result = confirm_with_io(
            &mut input,
            &mut stderr,
            true,
            "Продолжить?",
            "Будет завершен 1 сеанс",
        )
        .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(result, Confirmation::Confirmed);
        let rendered = String::from_utf8(stderr).unwrap_or_else(|error| panic!("{error}"));
        assert!(rendered.starts_with("Будет завершен 1 сеанс\n"));
        assert!(rendered.ends_with("Продолжить? [y/N]: "));
    }

    #[test]
    fn non_interactive_input_is_explicit_and_never_reads_an_answer() {
        let mut input = Cursor::new("yes\n".as_bytes());
        let mut stderr = Vec::new();

        let result = confirm_with_io(
            &mut input,
            &mut stderr,
            false,
            "Продолжить?",
            "Предпросмотр",
        )
        .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(result, Confirmation::NonInteractive);
        assert_eq!(input.position(), 0);
        assert_eq!(stderr, "Предпросмотр\n".as_bytes());
    }

    #[test]
    fn empty_or_unknown_answer_declines_safely() {
        for answer in ["\n", "maybe\n", "n\n"] {
            let mut input = Cursor::new(answer.as_bytes());
            let mut stderr = Vec::new();
            let result = confirm_with_io(&mut input, &mut stderr, true, "Удалить?", "")
                .unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(result, Confirmation::Declined);
        }
    }
}
