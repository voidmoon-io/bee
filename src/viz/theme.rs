//! Configurable themes (005-themes): the [`Theme`] model, the [`ThemeColor`] representation, the six
//! semantic [`Role`]s, resolution from CLI/env/config, and the process-wide active theme.
//!
//! The six roles are the *only* interface between the rendering code (`palette`, `buffer_render`, the
//! Python API) and the color system — nothing ever says "paint red", it says "paint the `error` role"
//! and the theme resolves it (spec Design). Colors are either basic-ANSI SGR codes (work on every
//! terminal, the `honeycomb` default) or 24-bit RGB (quantized to 256/16 colors when the terminal
//! lacks truecolor, reusing the `sprite_render` quantizers). The theme is loaded once at startup and
//! is immutable for the process lifetime (NFR-007) — `active_theme()` returns a `&'static Theme`.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::Deserialize;

use crate::viz::sprite_render::{quantize_16, quantize_256, ColorMode};
use crate::viz::themes;

/// A single theme color: a basic-ANSI SGR code that works everywhere, or a 24-bit RGB value that is
/// quantized down when the terminal cannot do truecolor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThemeColor {
    /// Basic-ANSI SGR params, e.g. `"31"` (red), `"32"` (green), `"2"` (dim), `"0"` (reset). Emitted
    /// verbatim as `\x1b[{code}m`; the terminal's color mode never changes it.
    Ansi(String),
    /// 24-bit RGB. Emitted as `\x1b[38;2;R;G;Bm` on truecolor terminals, else quantized to the
    /// xterm-256 cube (`38;5;N`) or the 16 basic colors.
    Rgb { r: u8, g: u8, b: u8 },
}

impl ThemeColor {
    /// The SGR **parameters** (no `\x1b[` / `m`) for this color under `mode`. `Ansi` passes through
    /// unchanged; `Rgb` renders truecolor or quantizes. Split out so `palette` can prepend `1;` for
    /// the bold variant, exactly as the legacy `bold`/`bold_if` did.
    pub fn sgr_params(&self, mode: ColorMode) -> String {
        match self {
            ThemeColor::Ansi(code) => code.clone(),
            ThemeColor::Rgb { r, g, b } => match mode {
                ColorMode::TrueColor => format!("38;2;{r};{g};{b}"),
                ColorMode::Ansi256 => format!("38;5;{}", quantize_256(*r, *g, *b)),
                ColorMode::Ansi16 => {
                    let n = quantize_16(*r, *g, *b);
                    let code = if n < 8 { 30 + n } else { 90 + (n - 8) };
                    code.to_string()
                }
            },
        }
    }
}

/// The six semantic color roles — the whole interface between rendering and the palette.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Pass, allowed, ✓, green states.
    Success,
    /// Fail, denied, ✗, red states.
    Error,
    /// Info, banners, identity, the bee.
    Info,
    /// Secondary: footers, metadata, tool args.
    Dim,
    /// Highlights, steering, links.
    Accent,
    /// Default text (terminal fg).
    Text,
}

/// A resolved theme: the six semantic roles plus an optional extended palette of named colors for
/// charts, sprites, and the Python API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Theme {
    pub name: String,
    pub success: ThemeColor,
    pub error: ThemeColor,
    pub info: ThemeColor,
    pub dim: ThemeColor,
    pub accent: ThemeColor,
    pub text: ThemeColor,
    /// Additional named colors (`pink`, `mauve`, `teal`, …) — not semantic roles, but the theme's
    /// coordinated palette for data viz. `chart.color("pink")` resolves here.
    pub extended: BTreeMap<String, ThemeColor>,
}

impl Theme {
    /// The color for `role`.
    pub fn get(&self, role: Role) -> &ThemeColor {
        match role {
            Role::Success => &self.success,
            Role::Error => &self.error,
            Role::Info => &self.info,
            Role::Dim => &self.dim,
            Role::Accent => &self.accent,
            Role::Text => &self.text,
        }
    }

    /// An extended color by (case-insensitive) name, if the theme defines it.
    pub fn extended(&self, name: &str) -> Option<&ThemeColor> {
        self.extended.get(&name.to_ascii_lowercase())
    }
}

/// Resolve a color *name* against `theme` (spec FR-051): a semantic role (or its honeycomb alias), an
/// extended-palette entry, a bare `#RRGGBB` hex, a basic color word, else the `text` role.
pub fn resolve_color_name(theme: &Theme, name: &str) -> ThemeColor {
    let n = name.trim().to_ascii_lowercase();
    // 1. semantic role (and the honeycomb aliases from 003).
    let role = match n.as_str() {
        "success" | "pollen" => Some(Role::Success),
        "error" | "sting" => Some(Role::Error),
        "info" | "honey" => Some(Role::Info),
        "dim" | "smoke" => Some(Role::Dim),
        "accent" | "royal" => Some(Role::Accent),
        "text" | "comb" => Some(Role::Text),
        _ => None,
    };
    if let Some(r) = role {
        return theme.get(r).clone();
    }
    // 2. extended palette.
    if let Some(c) = theme.extended(&n) {
        return c.clone();
    }
    // 3. bare hex.
    if n.starts_with('#') {
        if let Some((r, g, b)) = parse_hex(&n) {
            return ThemeColor::Rgb { r, g, b };
        }
    }
    // 4. basic color word → ANSI code.
    if let Some(code) = basic_word(&n) {
        return ThemeColor::Ansi(code.to_string());
    }
    // 5. fall back to the default text color.
    theme.text.clone()
}

/// A basic color word → its ANSI fg SGR code.
fn basic_word(name: &str) -> Option<&'static str> {
    Some(match name {
        "black" => "30",
        "red" => "31",
        "green" => "32",
        "yellow" => "33",
        "blue" => "34",
        "magenta" => "35",
        "cyan" => "36",
        "white" => "37",
        "gray" | "grey" => "90",
        _ => return None,
    })
}

/// Parse `"#RRGGBB"` (or `"RRGGBB"`) to an RGB triple.
pub fn parse_hex(s: &str) -> Option<(u8, u8, u8)> {
    let h = s.trim().strip_prefix('#').unwrap_or(s.trim());
    if h.len() != 6 {
        return None;
    }
    Some((
        u8::from_str_radix(&h[0..2], 16).ok()?,
        u8::from_str_radix(&h[2..4], 16).ok()?,
        u8::from_str_radix(&h[4..6], 16).ok()?,
    ))
}

/// Parse a theme-config color string: `#RRGGBB` → RGB, anything else → an ANSI code (verbatim).
fn parse_color_str(s: &str) -> Result<ThemeColor, String> {
    let s = s.trim();
    if s.starts_with('#') {
        return parse_hex(s)
            .map(|(r, g, b)| ThemeColor::Rgb { r, g, b })
            .ok_or_else(|| format!("bad hex color {s:?} (want #RRGGBB)"));
    }
    if s.is_empty() {
        return Err("empty color".into());
    }
    Ok(ThemeColor::Ansi(s.to_string()))
}

// --- Config file shape -----------------------------------------------------------------------

/// The `[theme]` section of `~/.config/bee/config.toml` (all fields optional): a built-in `name`,
/// per-role overrides, and extra `[theme.extended]` colors.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ThemeConfig {
    pub name: Option<String>,
    pub success: Option<String>,
    pub error: Option<String>,
    pub info: Option<String>,
    pub dim: Option<String>,
    pub accent: Option<String>,
    pub text: Option<String>,
    #[serde(default)]
    pub extended: BTreeMap<String, String>,
}

impl ThemeConfig {
    /// Whether any of the six role fields is set (⇒ the config defines a custom/override theme).
    fn has_roles(&self) -> bool {
        self.success.is_some()
            || self.error.is_some()
            || self.info.is_some()
            || self.dim.is_some()
            || self.accent.is_some()
            || self.text.is_some()
    }
}

/// The root config file: only the `[theme]` section concerns us here.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RootConfig {
    pub theme: Option<ThemeConfig>,
}

// --- Resolution ------------------------------------------------------------------------------

/// Resolve the active theme from the three sources in priority order (spec FR-046/047/048/052):
/// CLI flag > `BEE_THEME` env > config `[theme]` > `honeycomb`. Per-role overrides in the config
/// always layer on top of the resolved base. Returns the theme plus an optional warning string (an
/// unknown *named* theme falls back to `honeycomb` but never fails — FR-052).
pub fn resolve(
    cli: Option<&str>,
    env: Option<&str>,
    cfg: Option<&ThemeConfig>,
) -> (Theme, Option<String>) {
    let mut warning = None;

    // The base theme name (built-in selector), in priority order.
    let base_name = cli
        .map(str::to_string)
        .or_else(|| env.map(str::to_string))
        .or_else(|| cfg.and_then(|c| c.name.clone()));

    let has_roles = cfg.map(ThemeConfig::has_roles).unwrap_or(false);
    // A name set only via config (not CLI/env) may name a brand-new custom theme defined inline.
    let name_from_config_only = cli.is_none() && env.is_none();

    let mut theme = match base_name {
        // "auto" is a selector, not a theme: pick a flavor by what the terminal is actually
        // painting. Undetectable (no tty, silent emulator) falls back to honeycomb, whose basic
        // ANSI adapts to the terminal's own palette on either background.
        Some(n) if n.trim().eq_ignore_ascii_case("auto") => {
            theme_for_background(crate::viz::background::detect())
        }
        Some(n) => match themes::builtin(&n) {
            Some(t) => t,
            None if name_from_config_only && has_roles => {
                // A custom theme defined inline in the config, named `n`. Start from the honeycomb
                // defaults; the per-role overrides below fill it in.
                Theme {
                    name: n,
                    ..themes::honeycomb()
                }
            }
            None => {
                warning = Some(format!("unknown theme '{n}', using 'honeycomb'"));
                themes::honeycomb()
            }
        },
        None if has_roles => {
            // No name anywhere, but the config defines roles ⇒ an unnamed custom theme.
            Theme {
                name: "custom".into(),
                ..themes::honeycomb()
            }
        }
        None => themes::honeycomb(),
    };

    if let Some(c) = cfg {
        apply_overrides(&mut theme, c, &mut warning);
    }
    (theme, warning)
}

/// The theme `auto` resolves to for a detected background: the light catppuccin flavor on a light
/// terminal, the dark one on a dark terminal, honeycomb when detection came up empty. Pure — the
/// impure `detect()` call stays at the single `resolve` site so this mapping is testable.
fn theme_for_background(bg: Option<crate::viz::background::Background>) -> Theme {
    match bg {
        Some(crate::viz::background::Background::Light) => themes::catppuccin_latte(),
        Some(crate::viz::background::Background::Dark) => themes::catppuccin_mocha(),
        None => themes::honeycomb(),
    }
}

/// Layer a config's per-role overrides and extended entries onto `theme` (FR-047/FR-048). A color
/// string that fails to parse is skipped with a warning rather than aborting.
fn apply_overrides(theme: &mut Theme, cfg: &ThemeConfig, warning: &mut Option<String>) {
    let mut set = |field: &mut ThemeColor, val: &Option<String>, role: &str| {
        if let Some(s) = val {
            match parse_color_str(s) {
                Ok(c) => *field = c,
                Err(e) => set_warning(warning, format!("theme role '{role}': {e}")),
            }
        }
    };
    set(&mut theme.success, &cfg.success, "success");
    set(&mut theme.error, &cfg.error, "error");
    set(&mut theme.info, &cfg.info, "info");
    set(&mut theme.dim, &cfg.dim, "dim");
    set(&mut theme.accent, &cfg.accent, "accent");
    set(&mut theme.text, &cfg.text, "text");

    for (k, v) in &cfg.extended {
        match parse_color_str(v) {
            Ok(c) => {
                theme.extended.insert(k.to_ascii_lowercase(), c);
            }
            Err(e) => set_warning(warning, format!("theme extended '{k}': {e}")),
        }
    }
}

/// Keep the first warning (unknown-theme takes precedence over later parse warnings).
fn set_warning(slot: &mut Option<String>, msg: String) {
    if slot.is_none() {
        *slot = Some(msg);
    }
}

/// The `bee` config path: `$XDG_CONFIG_HOME/bee/config.toml`, else `$HOME/.config/bee/config.toml`.
/// No `dirs` crate (NFR-008) — resolved from env directly.
pub fn config_path() -> Option<std::path::PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return Some(
                std::path::PathBuf::from(xdg)
                    .join("bee")
                    .join("config.toml"),
            );
        }
    }
    let home = std::env::var_os("HOME")?;
    Some(
        std::path::PathBuf::from(home)
            .join(".config")
            .join("bee")
            .join("config.toml"),
    )
}

/// Read + parse the `[theme]` section of the config file, if present and well-formed. A missing or
/// malformed file yields `None` (theming is optional; a bad file must not break startup).
fn read_config_theme() -> Option<ThemeConfig> {
    let path = config_path()?;
    let text = std::fs::read_to_string(&path).ok()?;
    let root: RootConfig = toml::from_str(&text).ok()?;
    root.theme
}

/// Load the active theme for real (reads `BEE_THEME` and the config file), given an optional CLI
/// `--theme` value. Returns the theme plus an optional warning for the caller to print.
pub fn load(cli: Option<&str>) -> (Theme, Option<String>) {
    let env = std::env::var("BEE_THEME").ok();
    let cfg = read_config_theme();
    resolve(cli, env.as_deref(), cfg.as_ref())
}

// --- Active theme (process-global) -----------------------------------------------------------

static ACTIVE: OnceLock<Theme> = OnceLock::new();

/// Install the process-wide active theme. Call once at startup, before any rendering. A second call
/// (or a call after `active_theme()` already initialized the default) is a no-op.
pub fn init_theme(theme: Theme) {
    let _ = ACTIVE.set(theme);
}

/// The process-wide active theme, defaulting to `honeycomb` if `init_theme` was never called
/// (NFR-007: returns a `&'static Theme`, no per-call cost beyond the `OnceLock` read).
pub fn active_theme() -> &'static Theme {
    ACTIVE.get_or_init(themes::honeycomb)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ansi_passes_through_every_mode() {
        let c = ThemeColor::Ansi("33".into());
        for m in [ColorMode::TrueColor, ColorMode::Ansi256, ColorMode::Ansi16] {
            assert_eq!(c.sgr_params(m), "33");
        }
    }

    #[test]
    fn rgb_renders_or_quantizes_by_mode() {
        // #f9e2af = (249, 226, 175).
        let c = ThemeColor::Rgb {
            r: 249,
            g: 226,
            b: 175,
        };
        assert_eq!(c.sgr_params(ColorMode::TrueColor), "38;2;249;226;175"); // SC-029 shape
        assert!(c.sgr_params(ColorMode::Ansi256).starts_with("38;5;")); // SC-034 shape
                                                                        // 16-color quantization yields a basic/bright fg code (30–37 or 90–97).
        let p = c.sgr_params(ColorMode::Ansi16);
        let n: u16 = p.parse().unwrap();
        assert!((30..=37).contains(&n) || (90..=97).contains(&n), "got {p}");
    }

    #[test]
    fn unknown_named_theme_warns_and_falls_back() {
        // SC-035 / US11.4.
        let (t, warn) = resolve(Some("nonexistent"), None, None);
        assert_eq!(t.name, "honeycomb");
        assert!(warn.unwrap().contains("nonexistent"));
    }

    #[test]
    fn cli_beats_env_beats_config() {
        let cfg = ThemeConfig {
            name: Some("nord".into()),
            ..Default::default()
        };
        let (t, _) = resolve(Some("dracula"), Some("catppuccin-mocha"), Some(&cfg));
        assert_eq!(t.name, "dracula");
        let (t, _) = resolve(None, Some("catppuccin-mocha"), Some(&cfg));
        assert_eq!(t.name, "catppuccin-mocha");
        let (t, _) = resolve(None, None, Some(&cfg));
        assert_eq!(t.name, "nord");
    }

    #[test]
    fn fully_custom_theme_from_config() {
        // SC-032 / US12.1: all six roles as hex ⇒ Rgb everywhere.
        let cfg = ThemeConfig {
            name: Some("my-custom".into()),
            success: Some("#00ff00".into()),
            error: Some("#ff0000".into()),
            info: Some("#ffff00".into()),
            dim: Some("#808080".into()),
            accent: Some("#00ffff".into()),
            text: Some("#ffffff".into()),
            extended: BTreeMap::from([("highlight".into(), "#ff00ff".into())]),
        };
        let (t, warn) = resolve(None, None, Some(&cfg));
        assert!(warn.is_none(), "custom theme should not warn: {warn:?}");
        assert_eq!(t.name, "my-custom");
        assert_eq!(t.success, ThemeColor::Rgb { r: 0, g: 255, b: 0 });
        assert_eq!(
            t.text,
            ThemeColor::Rgb {
                r: 255,
                g: 255,
                b: 255
            }
        );
        assert_eq!(
            t.extended("highlight"),
            Some(&ThemeColor::Rgb {
                r: 255,
                g: 0,
                b: 255
            })
        );
    }

    #[test]
    fn builtin_with_role_override() {
        // US12.2: name = catppuccin-mocha, info override to peach (#fab387).
        let cfg = ThemeConfig {
            name: Some("catppuccin-mocha".into()),
            info: Some("#fab387".into()),
            ..Default::default()
        };
        let (t, _) = resolve(None, None, Some(&cfg));
        assert_eq!(
            t.info,
            ThemeColor::Rgb {
                r: 0xfa,
                g: 0xb3,
                b: 0x87
            }
        );
        // Other roles keep the mocha defaults.
        assert_eq!(
            t.error,
            ThemeColor::Rgb {
                r: 0xf3,
                g: 0x8b,
                b: 0xa8
            }
        );
    }

    #[test]
    fn auto_maps_backgrounds_to_flavors_and_unknown_to_honeycomb() {
        use crate::viz::background::Background;
        assert_eq!(
            theme_for_background(Some(Background::Light)).name,
            "catppuccin-latte"
        );
        assert_eq!(
            theme_for_background(Some(Background::Dark)).name,
            "catppuccin-mocha"
        );
        // Undetectable: honeycomb's basic ANSI is the choice that is safe on either background.
        assert_eq!(theme_for_background(None).name, "honeycomb");
    }

    #[test]
    fn resolve_color_name_precedence() {
        let t = themes::catppuccin_mocha();
        // role
        assert_eq!(resolve_color_name(&t, "accent"), t.accent); // SC-033
                                                                // honeycomb alias → role
        assert_eq!(resolve_color_name(&t, "honey"), t.info);
        // extended
        assert_eq!(resolve_color_name(&t, "pink"), t.extended["pink"]);
        // bare hex
        assert_eq!(
            resolve_color_name(&t, "#010203"),
            ThemeColor::Rgb { r: 1, g: 2, b: 3 }
        );
        // basic word
        assert_eq!(resolve_color_name(&t, "red"), ThemeColor::Ansi("31".into()));
        // unknown → text
        assert_eq!(resolve_color_name(&t, "no-such-color"), t.text);
    }
}
