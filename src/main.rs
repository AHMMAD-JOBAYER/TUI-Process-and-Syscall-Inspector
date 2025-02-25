use std::{
    collections::HashSet,
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
    sync::mpsc::{self, Receiver},
    thread,
    time::{Duration, Instant},
};

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event as CEvent, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};

use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Terminal,
};

use sysinfo::{ProcessExt, System, SystemExt, PidExt};

use fuzzy_matcher::skim::SkimMatcherV2;
use fuzzy_matcher::FuzzyMatcher;

use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;

/// Represents a running process.
#[derive(Clone)]
struct ProcessInfo {
    pid: i32,
    name: String,
    cmd: String,
}

/// The two primary screens.
enum AppMode {
    ProcessSelection,
    SyscallMonitoring,
}

/// The main application state.
struct App {
    // Current mode.
    mode: AppMode,
    // Process selection fields.
    processes: Vec<ProcessInfo>,
    filtered_processes: Vec<ProcessInfo>,
    process_filter: String,
    selected_process: usize,
    // Syscall monitoring fields.
    target_pid: i32,
    target_process_name: String,
    unique_syscalls: HashSet<String>,
    syscall_log: Vec<String>,
    // Filtering mode for syscalls.
    filter_mode: bool,
    syscall_filter: String,
    filtered_syscalls: Vec<String>,
    // Child process running strace and a channel for its output.
    strace_child: Option<Child>,
    strace_receiver: Option<Receiver<String>>,
    // Fuzzy matcher.
    matcher: SkimMatcherV2,
}

impl App {
    fn new() -> Self {
        let processes = Self::get_processes();
        Self {
            mode: AppMode::ProcessSelection,
            filtered_processes: processes.clone(),
            processes,
            process_filter: String::new(),
            selected_process: 0,
            target_pid: 0,
            target_process_name: String::new(),
            unique_syscalls: HashSet::new(),
            syscall_log: Vec::new(),
            filter_mode: false,
            syscall_filter: String::new(),
            filtered_syscalls: Vec::new(),
            strace_child: None,
            strace_receiver: None,
            matcher: SkimMatcherV2::default(),
        }
    }

    /// Retrieves running processes using sysinfo.
    fn get_processes() -> Vec<ProcessInfo> {
        let mut system = System::new_all();
        system.refresh_all();
        let mut processes = Vec::new();
        for (pid, process) in system.processes() {
            processes.push(ProcessInfo {
                pid: pid.as_u32() as i32,
                name: process.name().to_string(),
                cmd: process.cmd().join(" "),
            });
        }
        processes.sort_by(|a, b| a.pid.cmp(&b.pid));
        processes
    }

    /// Updates the filtered process list based on the current filter string.
    fn update_filtered_processes(&mut self) {
        if self.process_filter.is_empty() {
            self.filtered_processes = self.processes.clone();
        } else {
            self.filtered_processes = self
                .processes
                .iter()
                .filter(|p| {
                    p.name.to_lowercase().contains(&self.process_filter.to_lowercase())
                        || p.cmd.to_lowercase().contains(&self.process_filter.to_lowercase())
                })
                .cloned()
                .collect();
        }
        if self.selected_process >= self.filtered_processes.len() {
            self.selected_process = 0;
        }
    }

    /// Updates the filtered syscall list based on the fuzzy query.
    fn update_filtered_syscalls(&mut self) {
        let query = self.syscall_filter.clone();
        if query.is_empty() {
            self.filtered_syscalls = self.unique_syscalls.iter().cloned().collect();
        } else {
            let mut results: Vec<(i64, String)> = self
                .unique_syscalls
                .iter()
                .filter_map(|s| self.matcher.fuzzy_match(s, &query).map(|score| (score, s.clone())))
                .collect();
            results.sort_by(|a, b| b.0.cmp(&a.0));
            self.filtered_syscalls = results.into_iter().map(|(_, s)| s).collect();
        }
    }

    /// Spawns an `strace` process to monitor syscalls of the given PID.
    fn start_strace(&mut self, pid: i32) {
        let mut child = Command::new("strace")
            .arg("-p")
            .arg(pid.to_string())
            .arg("-e")
            .arg("trace=all")
            .arg("-f")
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to start strace. (Are you root?)");

        let stderr = child.stderr.take().expect("Failed to capture stderr");
        let (tx, rx) = mpsc::channel();

        thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                if let Ok(l) = line {
                    let _ = tx.send(l);
                }
            }
        });

        self.strace_child = Some(child);
        self.strace_receiver = Some(rx);
    }

    /// Stops the running strace process.
    fn stop_strace(&mut self) {
        if let Some(mut child) = self.strace_child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.strace_receiver = None;
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set up terminal.
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Update every 200ms.
    let tick_rate = Duration::from_millis(200);
    let mut app = App::new();
    let res = run_app(&mut terminal, &mut app, tick_rate);

    // Restore terminal.
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{:?}", err);
    }
    Ok(())
}

/// The main event loop.
fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
    tick_rate: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    // Declare last_tick inside run_app.
    let mut last_tick = Instant::now();

    loop {
        terminal.draw(|f| match app.mode {
            AppMode::ProcessSelection => draw_process_selection(f, app),
            AppMode::SyscallMonitoring => draw_syscall_monitoring(f, app),
        })?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));
        if crossterm::event::poll(timeout)? {
            if let CEvent::Key(key) = event::read()? {
                match app.mode {
                    AppMode::ProcessSelection => match key.code {
                        KeyCode::Char('q') => return Ok(()),
                        KeyCode::Char(c) => {
                            app.process_filter.push(c);
                            app.update_filtered_processes();
                        }
                        KeyCode::Backspace => {
                            app.process_filter.pop();
                            app.update_filtered_processes();
                        }
                        KeyCode::Down => {
                            if app.selected_process + 1 < app.filtered_processes.len() {
                                app.selected_process += 1;
                            }
                        }
                        KeyCode::Up => {
                            if app.selected_process > 0 {
                                app.selected_process -= 1;
                            }
                        }
                        KeyCode::Enter => {
                            if !app.filtered_processes.is_empty() {
                                let proc = &app.filtered_processes[app.selected_process];
                                app.target_pid = proc.pid;
                                app.target_process_name = proc.name.clone();
                                app.mode = AppMode::SyscallMonitoring;
                                app.unique_syscalls.clear();
                                app.syscall_log.clear();
                                app.filter_mode = false;
                                app.syscall_filter.clear();
                                app.filtered_syscalls.clear();
                                app.start_strace(proc.pid);
                            }
                        }
                        _ => {}
                    },
                    AppMode::SyscallMonitoring => {
                        if app.filter_mode {
                            // Fuzzy filtering mode.
                            match key.code {
                                KeyCode::Char(c) => {
                                    app.syscall_filter.push(c);
                                    app.update_filtered_syscalls();
                                }
                                KeyCode::Backspace => {
                                    app.syscall_filter.pop();
                                    app.update_filtered_syscalls();
                                }
                                KeyCode::Enter | KeyCode::Esc => {
                                    app.filter_mode = false;
                                    app.syscall_filter.clear();
                                }
                                _ => {}
                            }
                        } else {
                            // Live monitoring mode.
                            match key.code {
                                KeyCode::Char('q') | KeyCode::Char('b') => {
                                    app.stop_strace();
                                    app.mode = AppMode::ProcessSelection;
                                    app.processes = App::get_processes();
                                    app.update_filtered_processes();
                                }
                                KeyCode::Char('k') => {
                                    let pid = app.target_pid;
                                    let _ = signal::kill(Pid::from_raw(pid), Signal::SIGKILL);
                                    app.stop_strace();
                                    app.mode = AppMode::ProcessSelection;
                                    app.processes = App::get_processes();
                                    app.update_filtered_processes();
                                }
                                KeyCode::Char('f') => {
                                    app.filter_mode = true;
                                    app.update_filtered_syscalls();
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }

        // Update on tick.
        if last_tick.elapsed() >= tick_rate {
            if let AppMode::SyscallMonitoring = app.mode {
                if !app.filter_mode {
                    if let Some(rx) = &app.strace_receiver {
                        while let Ok(line) = rx.try_recv() {
                            if let Some(syscall) = parse_syscall(&line) {
                                if app.unique_syscalls.insert(syscall.clone()) {
                                    app.syscall_log.push(syscall);
                                }
                            }
                        }
                    }
                }
                if let Some(child) = &mut app.strace_child {
                    if let Ok(Some(_)) = child.try_wait() {
                        // Process ended.
                        app.stop_strace();
                        app.mode = AppMode::ProcessSelection;
                        app.processes = App::get_processes();
                        app.update_filtered_processes();
                    }
                }
            }
            last_tick = Instant::now();
        }
    }
}

/// Extracts a syscall name from a strace line.
fn parse_syscall(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    if !trimmed.chars().next()?.is_alphabetic() {
        return None;
    }
    trimmed.find('(').map(|idx| trimmed[..idx].to_string())
}

/// Renders the process selection screen.
fn draw_process_selection<B: ratatui::backend::Backend>(f: &mut ratatui::Frame<B>, app: &App) {
    let size = f.size();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints(
            [
                Constraint::Length(3),
                Constraint::Min(5),
                Constraint::Length(3),
            ]
            .as_ref(),
        )
        .split(size);

    let filter = Paragraph::new(app.process_filter.as_ref())
        .block(Block::default().borders(Borders::ALL).title("Fuzzy Filter"));
    f.render_widget(filter, chunks[0]);

    let items: Vec<ListItem> = app
        .filtered_processes
        .iter()
        .map(|p| ListItem::new(format!("{} - {} [{}]", p.pid, p.name, p.cmd)))
        .collect();

    let process_list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Processes"))
        .highlight_style(Style::default().bg(Color::Blue));

    // Use ratatui's built-in ListState.
    let mut state = ListState::default();
    state.select(Some(app.selected_process));
    f.render_stateful_widget(process_list, chunks[1], &mut state);

    let instructions = Paragraph::new("Up/Down: Navigate | Type: Filter | Enter: Select | q: Quit")
        .block(Block::default().borders(Borders::ALL).title("Instructions"));
    f.render_widget(instructions, chunks[2]);
}

/// Renders the syscall monitoring screen.
fn draw_syscall_monitoring<B: ratatui::backend::Backend>(f: &mut ratatui::Frame<B>, app: &App) {
    let size = f.size();
    let chunks = if app.filter_mode {
        Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints(
                [
                    Constraint::Length(3), // header
                    Constraint::Min(5),    // syscall list
                    Constraint::Length(3), // filter input
                    Constraint::Length(3), // instructions
                ]
                .as_ref(),
            )
            .split(size)
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints(
                [
                    Constraint::Length(3), // header
                    Constraint::Min(5),    // syscall list
                    Constraint::Length(3), // instructions
                ]
                .as_ref(),
            )
            .split(size)
    };

    let header = Paragraph::new(format!(
        "Monitoring syscalls for PID: {} ({})",
        app.target_pid, app.target_process_name
    ))
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(header, chunks[0]);

    let syscalls: Vec<String> = if app.filter_mode {
        app.filtered_syscalls.clone()
    } else {
        let mut v: Vec<String> = app.unique_syscalls.iter().cloned().collect();
        v.sort();
        v
    };

    let items: Vec<ListItem> = syscalls.iter().map(|s| ListItem::new(s.as_str())).collect();
    let syscall_list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Unique Syscalls"));
    f.render_widget(syscall_list, chunks[1]);

    if app.filter_mode {
        let filter_input = Paragraph::new(app.syscall_filter.as_ref())
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Syscall Fuzzy Filter (Enter/Esc to resume)"),
            );
        f.render_widget(filter_input, chunks[2]);
        let instr = Paragraph::new("Type to filter | k: Kill process | q or b: Back")
            .block(Block::default().borders(Borders::ALL).title("Instructions"));
        f.render_widget(instr, chunks[3]);
    } else {
        let instr = Paragraph::new("f: Filter syscalls | k: Kill process | q or b: Back")
            .block(Block::default().borders(Borders::ALL).title("Instructions"));
        f.render_widget(instr, chunks[2]);
    }
}
