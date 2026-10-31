//! `cargo run --example bee_preview -- --animate` plays the mascot's idle loop.
//! Add `--mood thinking` (or working, finished, waiting, concerned).
//! `--json` exports the greeting; `--moods-json` exports all expression sequences.
use std::io::{self, IsTerminal, Write};
use std::time::Instant;

use bee::viz::animator::redraw_block;
use bee::viz::bee as mascot;
use bee::viz::sprite_render::{render_frame_with, ColorMode};

fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.iter().any(|arg| arg == "--moods-json") {
        let moods: Vec<_> = mascot::Mood::ALL.into_iter().map(|mood| serde_json::json!({
            "name": mood.name(), "label": mood.label(),
            "animation": if mood == mascot::Mood::Idle { mascot::animation() } else { mascot::expression_animation(mood).clone() },
        })).collect();
        println!("{}", serde_json::to_string(&moods).unwrap());
        return Ok(());
    }
    let mood = if let Some(index) = args.iter().position(|arg| arg == "--mood") {
        let name = args
            .get(index + 1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "--mood needs a name"))?;
        mascot::Mood::ALL
            .into_iter()
            .find(|mood| mood.name() == name)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "mood must be idle, thinking, working, finished, waiting, or concerned",
                )
            })?
    } else {
        mascot::Mood::Idle
    };
    if args.iter().any(|arg| arg == "--json") {
        println!("{}", serde_json::to_string(&mascot::animation()).unwrap());
        return Ok(());
    }
    let tty = io::stdout().is_terminal();
    let animate = args.iter().any(|arg| arg == "--animate")
        && tty
        && std::env::var_os("BEE_NO_ANIMATION").is_none();
    let color = tty && bee::viz::palette::is_color_enabled();
    let mut stdout = io::stdout().lock();
    let start = Instant::now();
    let mut first = true;
    loop {
        let (pose, delay) = mascot::frame(mood, start.elapsed(), animate);
        let rows: Vec<_> = render_frame_with(pose, ColorMode::TrueColor, color)
            .into_iter()
            .map(|line| format!("  {line}"))
            .collect();
        if first {
            for row in &rows {
                writeln!(stdout, "{row}")?;
            }
            first = false;
        } else {
            write!(stdout, "{}", redraw_block(&rows))?;
        }
        stdout.flush()?;
        match delay {
            Some(delay) => std::thread::sleep(delay),
            None => return Ok(()),
        }
    }
}
