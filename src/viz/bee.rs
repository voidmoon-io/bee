//! Bee's cheeky pixel mascot. The resting pose greets the user; the short flap-and-wink
//! animation is available through `bee_animation()`. Both are deterministic and cached.

use std::sync::OnceLock;
use std::time::Duration;

use crate::render_spec::{AnimationSpec, SpriteSpec};

mod art;

fn build(rows: &[&str; art::SIZE as usize]) -> SpriteSpec {
    SpriteSpec {
        width: art::SIZE,
        height: art::SIZE,
        pixels: rows
            .iter()
            .flat_map(|row| row.bytes().map(art::pixel))
            .collect(),
    }
}

/// A 24×24 honey-gold sidekick: crooked antennae, a sidelong glance, and a small smirk.
/// Occupies 24 columns and 12 terminal rows using half-block pixels.
pub fn sprite() -> SpriteSpec {
    static BEE: OnceLock<SpriteSpec> = OnceLock::new();
    BEE.get_or_init(|| build(&art::REST)).clone()
}

fn wings_up() -> SpriteSpec {
    let mut frame = sprite();
    // Move only the exposed wing pixels, leaving the head and shoulders in front.
    for y in 8..14 {
        for x in (0..5).chain(21..24) {
            frame.pixels[y * 24 + x] = None;
        }
    }
    for (y, x, row) in [
        (6, 2, "BB"),
        (7, 1, "BWWB"),
        (8, 1, "BWWB"),
        (9, 2, "BWB"),
        (10, 3, "BB"),
        (6, 21, "BB"),
        (7, 21, "BWB"),
        (8, 21, "BWB"),
        (9, 21, "BWB"),
        (10, 21, "BB"),
    ] {
        for (offset, c) in row.bytes().enumerate() {
            frame.pixels[y * 24 + x + offset] = art::pixel(c);
        }
    }
    frame
}

fn wink() -> SpriteSpec {
    let mut frame = sprite();
    for (y, row) in [(10, "HHHH"), (11, "KKKH")] {
        for (offset, c) in row.bytes().enumerate() {
            frame.pixels[y * 24 + 15 + offset] = art::pixel(c);
        }
    }
    frame
}

/// One 720 ms greeting: flutter, wink, and settle back into the resting pose.
fn greeting() -> &'static AnimationSpec {
    static ANIM: OnceLock<AnimationSpec> = OnceLock::new();
    ANIM.get_or_init(|| AnimationSpec {
        frames: vec![sprite(), wings_up(), sprite(), wink(), wings_up(), sprite()],
        interval_ms: 120,
        bounce: false,
        cycles: 1,
    })
}

/// One 720 ms greeting, ending in the resting pose.
pub fn animation() -> AnimationSpec {
    greeting().clone()
}

/// A brief flutter and wink every 4.8 seconds, with a still pause between greetings.
/// Returns the pose and the time until it changes, so a resting bee needs no frame polling.
pub fn idle_frame(elapsed: Duration) -> (&'static SpriteSpec, Duration) {
    let greeting = greeting();
    let phase = (elapsed.as_millis() % 4_800) as u64;
    let interval = greeting.interval_ms;
    let last = greeting.frames.len() - 1;
    let index = (phase / interval).min(last as u64) as usize;
    let next = if index == last {
        4_800
    } else {
        (index as u64 + 1) * interval
    };
    (&greeting.frames[index], Duration::from_millis(next - phase))
}

/// Expressions describe observed session activity, never inferred progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mood {
    Idle,
    Thinking,
    Working,
    Finished,
    Waiting,
    Concerned,
}

impl Mood {
    pub const ALL: [Self; 6] = [
        Self::Idle,
        Self::Thinking,
        Self::Working,
        Self::Finished,
        Self::Waiting,
        Self::Concerned,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Thinking => "thinking",
            Self::Working => "working",
            Self::Finished => "finished",
            Self::Waiting => "waiting",
            Self::Concerned => "concerned",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Idle => "ready",
            Self::Thinking => "thinking",
            Self::Working => "running tool",
            Self::Finished | Self::Waiting => "your turn",
            Self::Concerned => "needs attention",
        }
    }
}

fn paint(frame: &mut SpriteSpec, x: usize, y: usize, rows: &[&str]) {
    for (dy, row) in rows.iter().enumerate() {
        for (dx, color) in row.bytes().enumerate() {
            frame.pixels[(y + dy) * usize::from(art::SIZE) + x + dx] = art::pixel(color);
        }
    }
}

fn expression(mood: Mood) -> SpriteSpec {
    let mut frame = sprite();
    match mood {
        Mood::Idle => {}
        Mood::Thinking => {
            // Pupils look up; the grin relaxes while Bee considers the response.
            paint(&mut frame, 8, 9, &["HHHH", "WKKW", "WWWW"]);
            paint(&mut frame, 15, 9, &["HHHH", "WKKW", "WWWW"]);
            paint(&mut frame, 11, 13, &["HHHHHH", "HHKKHH"]);
        }
        Mood::Working => {
            paint(&mut frame, 8, 9, &["KKHH", "WWWK", "WWKK"]);
            paint(&mut frame, 15, 9, &["HHKK", "WWWK", "WWKK"]);
            paint(&mut frame, 11, 13, &["HHHHHH", "HKKKKH"]);
        }
        Mood::Finished => {
            paint(&mut frame, 8, 9, &["HHHH", "HKKH", "KHHK"]);
            paint(&mut frame, 15, 9, &["HHHH", "HKKH", "KHHK"]);
        }
        Mood::Waiting => {
            paint(&mut frame, 8, 8, &["KKKH", "HHHH", "WWKW", "WWKK"]);
            paint(&mut frame, 15, 9, &["HHHH", "WKWW", "KKWW"]);
            // A one-pixel head tilt, while the body and wings stay planted.
            let face = frame.clone();
            for y in 5..16 {
                for x in 5..21 {
                    frame.pixels[y * 24 + x] =
                        face.pixel(x as u16, (y + usize::from(x < 13)) as u16);
                }
            }
        }
        Mood::Concerned => {
            paint(&mut frame, 8, 9, &["HHKK", "WWKW", "WWKK"]);
            paint(&mut frame, 15, 9, &["KKHH", "WKWW", "KKWW"]);
            paint(&mut frame, 11, 13, &["HHKKHH", "HKHHKH"]);
        }
    }
    frame
}

fn twitch(mut frame: SpriteSpec) -> SpriteSpec {
    paint(&mut frame, 7, 1, &["...", "...", "...", "..."]);
    paint(&mut frame, 8, 1, &[".KK", "K..", "K..", ".K."]);
    frame
}

fn flap(mut frame: SpriteSpec) -> SpriteSpec {
    let up = wings_up();
    for y in 6..14 {
        for x in (0..5).chain(21..24) {
            frame.pixels[y * 24 + x] = up.pixels[y * 24 + x];
        }
    }
    frame
}

fn nod(frame: &SpriteSpec) -> SpriteSpec {
    let mut bowed = frame.clone();
    for y in 1..16 {
        for x in 5..21 {
            bowed.pixels[y * 24 + x] = frame.pixel(x as u16, y as u16 - 1);
        }
    }
    bowed
}

/// Each sequence has a representative first pose for motion-off sessions.
/// Zero cycles means loop; finished and concerned reactions play just once.
pub fn expression_animation(mood: Mood) -> &'static AnimationSpec {
    static POSES: OnceLock<[AnimationSpec; 6]> = OnceLock::new();
    let poses = POSES.get_or_init(|| {
        Mood::ALL.map(|mood| {
            let pose = expression(mood);
            let (frames, interval_ms, cycles) = match mood {
                Mood::Idle => (vec![pose], 120, 0),
                Mood::Thinking => (
                    vec![
                        pose.clone(),
                        twitch(pose.clone()),
                        pose.clone(),
                        pose.clone(),
                        pose.clone(),
                        pose,
                    ],
                    240,
                    0,
                ),
                Mood::Working => (vec![pose.clone(), flap(pose)], 120, 0),
                Mood::Finished => (
                    vec![pose.clone(), nod(&pose), pose, expression(Mood::Waiting)],
                    240,
                    1,
                ),
                Mood::Waiting => (
                    vec![
                        pose.clone(),
                        twitch(pose.clone()),
                        pose.clone(),
                        pose.clone(),
                        pose.clone(),
                        pose.clone(),
                        pose.clone(),
                        pose,
                    ],
                    500,
                    0,
                ),
                Mood::Concerned => (vec![pose.clone(), twitch(pose.clone()), pose], 240, 1),
            };
            AnimationSpec {
                frames,
                interval_ms,
                bounce: false,
                cycles,
            }
        })
    });
    &poses[match mood {
        Mood::Idle => 0,
        Mood::Thinking => 1,
        Mood::Working => 2,
        Mood::Finished => 3,
        Mood::Waiting => 4,
        Mood::Concerned => 5,
    }]
}

/// A pose plus its next redraw deadline. Settled one-shot reactions need no further ticks.
pub fn frame(
    mood: Mood,
    elapsed: Duration,
    animate: bool,
) -> (&'static SpriteSpec, Option<Duration>) {
    if mood == Mood::Idle && animate {
        let (pose, next) = idle_frame(elapsed);
        return (pose, Some(next));
    }
    let sequence = expression_animation(mood);
    if !animate {
        return (&sequence.frames[0], None);
    }
    let step = elapsed.as_millis() / u128::from(sequence.interval_ms);
    let len = sequence.frames.len();
    if sequence.cycles == 1 && step >= (len - 1) as u128 {
        return (&sequence.frames[len - 1], None);
    }
    let index = (step % len as u128) as usize;
    let delay =
        sequence.interval_ms - (elapsed.as_millis() % u128::from(sequence.interval_ms)) as u64;
    (&sequence.frames[index], Some(Duration::from_millis(delay)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expressions_remain_distinct_without_motion_and_reactions_settle() {
        for mood in Mood::ALL {
            let (still, delay) = frame(mood, Duration::from_secs(99), false);
            assert_eq!(delay, None);
            assert_eq!((still.width, still.height), (24, 24));
            assert_eq!(still.pixels.len(), 24 * 24);
            if mood != Mood::Idle {
                assert_ne!(still, &sprite());
            }
            for pose in &expression_animation(mood).frames {
                assert_eq!((pose.width, pose.height), (24, 24));
                assert_eq!(pose.pixels.len(), 24 * 24);
            }
        }
        for mood in [Mood::Finished, Mood::Concerned] {
            assert!(frame(mood, Duration::ZERO, true).1.is_some());
            assert_eq!(frame(mood, Duration::from_secs(2), true).1, None);
        }
        assert_eq!(
            frame(Mood::Finished, Duration::from_secs(2), true).0,
            frame(Mood::Waiting, Duration::ZERO, false).0
        );
        assert_ne!(
            frame(Mood::Working, Duration::ZERO, true).0,
            frame(Mood::Working, Duration::from_millis(120), true).0
        );
    }

    #[test]
    fn idle_cycle_pauses_and_wraps_without_polling_the_resting_pose() {
        let (rest, next) = idle_frame(Duration::ZERO);
        assert_eq!(rest, &sprite());
        assert_eq!(next, Duration::from_millis(120));
        assert_ne!(idle_frame(Duration::from_millis(120)).0, rest);
        assert_eq!(idle_frame(Duration::from_millis(360)).0, &wink());
        assert_eq!(
            idle_frame(Duration::from_millis(600)),
            (rest, Duration::from_millis(4200))
        );
        assert_eq!(idle_frame(Duration::from_millis(4800)), (rest, next));
        assert_eq!(
            idle_frame(Duration::from_millis(4920)).0,
            idle_frame(Duration::from_millis(120)).0
        );
    }

    #[test]
    fn greeting_is_valid_and_settles_back_to_the_banner() {
        let still = sprite();
        let greeting = animation();
        assert!(art::REST.iter().all(|row| row.len() == art::SIZE as usize));
        for frame in &greeting.frames {
            assert_eq!((frame.width, frame.height), (still.width, still.height));
            assert_eq!(frame.pixels.len(), usize::from(frame.width * frame.height));
            assert!(!frame.is_fully_transparent());
        }
        assert_eq!(greeting.frames.first(), Some(&still));
        assert_eq!(greeting.frames.last(), Some(&still));
        assert!(greeting.frames.iter().any(|frame| frame != &still));
        assert_eq!(greeting.cycles, 1);
        assert!(!greeting.bounce);
    }
}
