use std::{
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    io::{BufReader, BufRead},
    fs::File,
};
use tui::{
    backend::CrosstermBackend, layout::{Constraint, Direction, Layout}, style::{Color, Style}, widgets::{Block, Borders, List, ListItem, ListState, Paragraph}, Terminal
};
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen}
};
use sysinfo::{System, SystemExt, Pid, ProcessExt, PidExt};
use nix::sys::signal::Signal;

struct AppState {
    processes: Vec<(Pid, String)>,
    list_state: ListState,
    monitoring_pid: Option<Pid>,
    syscalls: Arc<Mutex<Vec<String>>>,
    log_file: Option<String>
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = AppState {
        processes: vec![],
        list_state: ListState::default(),
        monitoring_pid: None,
        syscalls: Arc::new(Mutex::new(vec![])),
        log_file: None
    };
    app.list_state.select(Some(0));

    loop {
        terminal.draw(|f| {
            let size = f.size();
            if app.monitoring_pid.is_none() {
                // Process selection view
                let items: Vec<ListItem> = app.processes.iter()
                    .map(|(pid, name)| ListItem::new(format!("{}: {}", pid, name)))
                    .collect();
                let list = List::new(items)
                    .block(Block::default().borders(Borders::ALL).title("Processes"))
                    .highlight_style(Style::default().bg(Color::Blue));
                f.render_stateful_widget(list, size, &mut app.list_state);
            } else {
                // Syscall monitoring view
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .margin(1)
                    .constraints([
                        Constraint::Percentage(80),
                        Constraint::Percentage(20)
                    ].as_ref())
                    .split(size);
                
                let syscalls = app.syscalls.lock().unwrap();
                let items: Vec<ListItem> = syscalls.iter()
                    .rev()
                    .take(chunks[0].height as usize - 2)
                    .map(|s| ListItem::new(s.clone()))
                    .collect();
                let list = List::new(items)
                    .block(Block::default().borders(Borders::ALL).title("Syscalls"));
                f.render_widget(list, chunks[0]);

                let help = Paragraph::new("[q] Back | [k] Kill | [↑↓] Scroll")
                    .block(Block::default().borders(Borders::ALL));
                f.render_widget(help, chunks[1]);
            }
        })?;

        if let Event::Key(key) = event::read()? {
            match (app.monitoring_pid.is_some(), key.code) {
                (false, KeyCode::Char('q')) => break,
                (false, KeyCode::Up) => {
                    let i = match app.list_state.selected() {
                        Some(i) => {
                            if i == 0 {
                                app.processes.len() - 1
                            } else {
                                i - 1
                            }
                        },
                        None => 0,
                    };
                    app.list_state.select(Some(i));
                },
                (false, KeyCode::Down) => {
                    let i = match app.list_state.selected() {
                        Some(i) => {
                            if i >= app.processes.len() - 1 {
                                0
                            } else {
                                i + 1
                            }
                        }
                        None => 0,
                    };
                    app.list_state.select(Some(i));
                },
                (false, KeyCode::Enter) => {
                    if let Some(selected) = app.list_state.selected() {
                        let pid = app.processes[selected].0;
                        start_monitoring(&mut app, pid)?;
                    }
                },
                (true, KeyCode::Char('q')) => {
                    app.monitoring_pid = None;
                    app.syscalls.lock().unwrap().clear();
                },
                (true, KeyCode::Char('k')) => {
                    if let Some(pid) = app.monitoring_pid {
                        nix::sys::signal::kill(
                            nix::unistd::Pid::from_raw(pid.as_u32() as i32),
                            Signal::SIGKILL
                        )?;
                        app.monitoring_pid = None;
                    }
                },
                _ => {}
            }
        }

        if app.monitoring_pid.is_none() {
            refresh_processes(&mut app);
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}

fn refresh_processes(app: &mut AppState) {
    let mut system = System::new_all();
    system.refresh_all();
    app.processes = system.processes()
        .iter()
        .map(|(&pid, process)| (pid, process.name().to_string()))
        .collect();
    app.processes.sort_by(|a, b| a.0.cmp(&b.0));
}

fn start_monitoring(app: &mut AppState, pid: Pid) -> Result<(), Box<dyn std::error::Error>> {
    let log_path = format!("/tmp/process_monitor_{}.log", pid);
    let _file = File::create(&log_path)?;
    app.log_file = Some(log_path);

    let strace = Command::new("strace")
        .arg("-p")
        .arg(pid.to_string())
        .arg("-f")
        .arg("-tt")
        .arg("-o")
        .arg(app.log_file.as_ref().unwrap())
        .stdout(Stdio::piped())
        .spawn()?;

    let syscalls = Arc::clone(&app.syscalls);
    thread::spawn(move || {
        let reader = BufReader::new(strace.stdout.unwrap());
        for line in reader.lines().filter_map(|l| l.ok()) {
            let mut calls = syscalls.lock().unwrap();
            calls.push(line);
            if calls.len() > 1000 {
                calls.remove(0);
            }
        }
    });

    app.monitoring_pid = Some(pid);
    Ok(())
}
