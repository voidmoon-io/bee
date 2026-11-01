use monty::{MontyRun, RunProgress};
use monty_types::{
    CompileOptions, MontyObject, PrintWriter, ResourceLimits, ResourceTracker,
    memory_limit_with_headroom,
};
use std::{
    env,
    fs::OpenOptions,
    io::{Read, Write},
    path::Path,
    time::Duration,
};

#[global_allocator]
static ALLOCATOR: monty_alloc::LimitedAllocator = monty_alloc::LimitedAllocator;

const MEMORY: usize = 16 * 1024 * 1024;
const MAX_SNAPSHOT: usize = 4 * 1024 * 1024;
const HEADER: &[u8] = b"bee-monty-spike/1;monty=1.4.0;postcard\n";
const PROGRAM: &str =
    "prefix = 7\nfirst = host(3)\nsecond = host(first + prefix)\nfirst + second + prefix";

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn limits() -> ResourceLimits {
    ResourceLimits {
        max_memory: Some(MEMORY),
        max_feed_duration: Some(Duration::from_secs(1)),
        ..ResourceLimits::default()
    }
}

fn save(path: &Path, progress: &RunProgress) -> Result<()> {
    let bytes = postcard::to_allocvec(progress)?;
    if bytes.len() > MAX_SNAPSHOT {
        return Err("snapshot too large".into());
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(HEADER)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

// Only load files this fixture produced in an operator-owned directory. This is not
// an authentication scheme or a production durable checkpoint store.
fn load(path: &Path) -> Result<RunProgress> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take((MAX_SNAPSHOT + HEADER.len() + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_SNAPSHOT + HEADER.len() {
        return Err("snapshot too large".into());
    }
    let body = bytes.strip_prefix(HEADER).ok_or("incompatible snapshot")?;
    Ok(postcard::from_bytes(body)?)
}

fn report(progress: RunProgress, destination: &Path) -> Result<()> {
    match &progress {
        RunProgress::FunctionCall(call) => {
            if call.function_name != "host" {
                return Err("unexpected host function".into());
            }
            save(destination, &progress)?;
            println!("suspended host {:?}", call.args.arg(0));
        }
        RunProgress::Complete(value) => println!("complete {value:?}"),
        _ => return Err("unsupported suspension".into()),
    }
    Ok(())
}

fn run() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    monty_alloc::set_hard_limit(memory_limit_with_headroom(Some(MEMORY), false))?;
    match args.get(1).map(String::as_str) {
        Some("start") if args.len() == 3 => {
            let runner = MontyRun::new(PROGRAM.into(), "fixture.py", vec!["host".into()], CompileOptions::default())?;
            let progress = runner.start(vec![MontyObject::function("host", None)], ResourceTracker::new(limits()), PrintWriter::Disabled)?;
            report(progress, Path::new(&args[2]))
        }
        Some("resume") if args.len() == 5 => {
            let RunProgress::FunctionCall(mut call) = load(Path::new(&args[2]))? else { return Err("expected suspended call".into()); };
            call.tracker_mut().tighten_limits(&limits());
            let value: i64 = args[3].parse()?;
            let progress = call.resume(MontyObject::int(value), PrintWriter::Disabled)?;
            report(progress, Path::new(&args[4]))
        }
        Some(mode @ ("memory" | "timeout" | "watchdog" | "allocator")) if args.len() == 2 => {
            if mode == "allocator" {
                // Bypass interpreter prechecks to prove the process allocator ceiling.
                let mut bytes = Vec::<u8>::with_capacity(256 * 1024 * 1024);
                bytes.push(1);
                std::hint::black_box(bytes);
                return Err("allocator ceiling did not fire".into());
            }
            let source = if mode == "memory" { "'x' * 100000000" } else { "while True: pass" };
            let mut budget = limits();
            budget.max_feed_duration = if mode == "watchdog" { None } else { Some(Duration::from_millis(50)) };
            let mut runner = MontyRun::new(source.into(), "limits.py", vec![], CompileOptions::default())?;
            runner.run(vec![], ResourceTracker::new(budget), PrintWriter::Disabled)?;
            Err("limit did not fire".into())
        }
        _ => Err("usage: start SNAPSHOT | resume SNAPSHOT VALUE NEXT | memory | timeout | watchdog | allocator".into()),
    }
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}
